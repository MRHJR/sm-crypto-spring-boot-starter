package io.github.mrhjr.smcrypto;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.mrhjr.smcrypto.core.Protocol;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.servlet.DispatcherType;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;

final class CryptoFilter extends OncePerRequestFilter {
    private static final String VERIFIED = CryptoFilter.class.getName() + ".verified";
    private static final ObjectMapper WIRE = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION);
    private static final byte[] INTERNAL_ERROR = "{\"code\":\"ENCRYPTED_ENDPOINT_ERROR\"}".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] HTTP_ERROR = "{\"code\":\"HTTP_ERROR\"}".getBytes(StandardCharsets.US_ASCII);
    private final PostPolicy policy;
    private final KeyRing keys;
    private final ReplayStore replay;
    private final long skew;
    private final int limit;
    private final SecureRandom random = new SecureRandom();

    CryptoFilter(CryptoProperties config, PostPolicy policy, KeyRing keys, ReplayStore replay) {
        this.keys = keys;
        this.replay = replay;
        this.policy = policy;
        this.limit = config.getMaxBodyBytes();
        if (limit < 1024 || limit > 8 * 1024 * 1024) {
            throw new IllegalArgumentException("sm-crypto.max-body-bytes must be in [1024, 8388608]");
        }
        Duration window = config.getClockSkew();
        if (window == null || window.compareTo(Duration.ofMillis(1)) < 0
                || window.compareTo(Duration.ofMinutes(15)) > 0) {
            throw new IllegalArgumentException("sm-crypto.clock-skew must be in [1ms, 15m]");
        }
        this.skew = window.toMillis();
    }

    static boolean isVerified(HttpServletRequest request) {
        Object marker = request.getAttribute(VERIFIED);
        return request.getDispatcherType() == DispatcherType.REQUEST && marker instanceof VerifiedRoute
                && ((VerifiedRoute) marker).path.equals(request.getRequestURI());
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return request.getDispatcherType() != DispatcherType.REQUEST
                || !policy.requiresEncryption(request.getMethod(), request.getRequestURI());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException {
        if (!PostPolicy.validExactPath(request.getRequestURI()) || request.getQueryString() != null
                || !isJson(request.getContentType()) || request.getHeader("Content-Encoding") != null) {
            writeProtocolError(response, 400, "INVALID_ENCRYPTED_REQUEST");
            return;
        }

        VerifiedEnvelope verified;
        try {
            verified = authenticate(request);
        } catch (BodyTooLarge ignored) {
            writeProtocolError(response, 413, "ENCRYPTED_REQUEST_TOO_LARGE");
            return;
        } catch (IOException | IllegalArgumentException e) {
            writeProtocolError(response, 400, "INVALID_ENCRYPTED_REQUEST");
            return;
        }

        BufferedCryptoResponse capture = new BufferedCryptoResponse(response, limit);
        byte[] clearResponse = null;
        try {
            request.setAttribute(VERIFIED, new VerifiedRoute(request.getRequestURI()));
            boolean failed = false;
            try {
                chain.doFilter(new BufferedCryptoRequest(request, verified.plaintext), capture);
            } catch (IOException | ServletException | RuntimeException failure) {
                // Do not expose downstream exception text or partial plaintext.
                failed = true;
            }
            int status = capture.getStatus();
            if (!failed && !capture.isOversized()) {
                clearResponse = capture.body();
                if (clearResponse.length == 0 && status >= 400 && status <= 599) {
                    clearResponse = HTTP_ERROR;
                } else if (status < 200 || status >= 600 || status == 204 || status == 205 || status == 304
                        || (status >= 300 && status < 400) || !isJson(capture.getContentType())
                        || clearResponse.length == 0) {
                    failed = true;
                }
            } else {
                failed = true;
            }
            if (failed) {
                status = 500;
                clearResponse = INTERNAL_ERROR;
            }
            writeEncrypted(response, verified.requestId, verified.responseKey, status, clearResponse);
        } finally {
            request.removeAttribute(VERIFIED);
            Arrays.fill(verified.plaintext, (byte) 0);
            Arrays.fill(verified.responseKey, (byte) 0);
            if (clearResponse != null && clearResponse != INTERNAL_ERROR && clearResponse != HTTP_ERROR) {
                Arrays.fill(clearResponse, (byte) 0);
            }
        }
    }

    private VerifiedEnvelope authenticate(HttpServletRequest request) throws IOException {
        long length = request.getContentLengthLong();
        if (length > limit) {
            throw new BodyTooLarge();
        }
        JsonNode envelope = parseEnvelope(readLimited(request.getInputStream(), limit));
        if (envelope == null || !envelope.isObject() || envelope.size() != 8
                || !envelope.path("version").isIntegralNumber() || !envelope.path("version").canConvertToInt()
                || envelope.path("version").intValue() != 1
                || !envelope.path("timestamp").isIntegralNumber() || !envelope.path("timestamp").canConvertToLong()) {
            throw invalid();
        }
        long timestamp = envelope.path("timestamp").longValue();
        long now = System.currentTimeMillis();
        if (timestamp < now - skew || timestamp > now + skew) {
            throw invalid();
        }
        String kid = field(envelope, "kid");
        String id = field(envelope, "requestId");
        if (!KeyRing.KID.matcher(kid).matches() || id.length() != 22 || Protocol.decode(id).length != 16) {
            throw invalid();
        }
        byte[] iv = binary(envelope, "iv", 12);
        byte[] tag = binary(envelope, "tag", 16);
        byte[] wrapped = binary(envelope, "wrappedKey", 129);
        byte[] ciphertext = Protocol.decode(field(envelope, "ciphertext"));
        if (ciphertext.length == 0) { throw invalid(); }
        byte[] sealed = Arrays.copyOf(ciphertext, ciphertext.length + tag.length);
        System.arraycopy(tag, 0, sealed, ciphertext.length, tag.length);
        byte[] aad = Protocol.requestAad(kid, id, timestamp, request.getMethod(), request.getRequestURI());
        byte[] keyBundle = keys.unwrap(kid, wrapped);
        byte[] requestKey = Arrays.copyOf(keyBundle, 16);
        byte[] responseKey = Arrays.copyOfRange(keyBundle, 16, 32);
        Arrays.fill(keyBundle, (byte) 0);
        byte[] decrypted = null;
        boolean admitted = false;
        try {
            if (MessageDigest.isEqual(requestKey, responseKey)) {
                throw invalid();
            }
            decrypted = Protocol.decrypt(requestKey, iv, sealed, aad);
            // Recheck time after cryptographic work and keep the ID for the full acceptance window.
            now = System.currentTimeMillis();
            if (timestamp < now - skew || timestamp > now + skew || !claim(id, timestamp + skew, now)) {
                throw invalid();
            }
            admitted = true;
            return new VerifiedEnvelope(id, responseKey, decrypted);
        } finally {
            Arrays.fill(requestKey, (byte) 0);
            if (!admitted) {
                Arrays.fill(responseKey, (byte) 0);
                if (decrypted != null) { Arrays.fill(decrypted, (byte) 0); }
            }
        }
    }

    private boolean claim(String id, long expiry, long now) {
        try {
            return replay.claim(id, expiry, now);
        } catch (RuntimeException unavailable) {
            return false;
        }
    }

    private void writeEncrypted(HttpServletResponse response, String id, byte[] key, int status, byte[] body)
            throws IOException {
        byte[] iv = new byte[12];
        random.nextBytes(iv);
        byte[] sealed = Protocol.encrypt(key, iv, body, Protocol.responseAad(id, status));
        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("version", 1);
        envelope.put("requestId", id);
        envelope.put("iv", Protocol.encode(iv));
        envelope.put("ciphertext", Protocol.encode(Arrays.copyOf(sealed, sealed.length - 16)));
        envelope.put("tag", Protocol.encode(Arrays.copyOfRange(sealed, sealed.length - 16, sealed.length)));
        writeJson(response, status, WIRE.writeValueAsBytes(envelope));
    }

    static void writeProtocolError(HttpServletResponse response, int status, String code) throws IOException {
        writeJson(response, status, WIRE.writeValueAsBytes(Collections.singletonMap("code", code)));
    }

    private static void writeJson(HttpServletResponse response, int status, byte[] json) throws IOException {
        response.resetBuffer();
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Cache-Control", "no-store");
        response.setContentLength(json.length);
        response.getOutputStream().write(json);
    }

    private static boolean isJson(String contentType) {
        if (contentType == null) { return false; }
        try {
            MediaType type = MediaType.parseMediaType(contentType);
            return "application".equalsIgnoreCase(type.getType())
                    && ("json".equalsIgnoreCase(type.getSubtype()) || type.getSubtype().endsWith("+json"));
        } catch (IllegalArgumentException invalid) {
            return false;
        }
    }

    private static String field(JsonNode item, String name) {
        JsonNode value = item.path(name);
        if (!value.isTextual()) { throw invalid(); }
        return value.textValue();
    }

    private static byte[] binary(JsonNode item, String name, int length) {
        String encoded = field(item, name);
        if (encoded.length() != (length * 8 + 5) / 6) { throw invalid(); }
        byte[] binary = Protocol.decode(encoded);
        if (binary.length != length) { throw invalid(); }
        return binary;
    }

    private static ObjectNode parseEnvelope(byte[] data) throws IOException {
        // The wire schema contains only eight scalar values. Never parse nested structures here.
        try (JsonParser parser = WIRE.getFactory().createParser(data)) {
            if (parser.nextToken() != JsonToken.START_OBJECT) {
                throw invalid();
            }
            ObjectNode result = WIRE.createObjectNode();
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                if (parser.currentToken() != JsonToken.FIELD_NAME || result.size() >= 8) {
                    throw invalid();
                }
                String name = parser.currentName();
                JsonToken value = parser.nextToken();
                if ("version".equals(name) || "timestamp".equals(name)) {
                    if (value != JsonToken.VALUE_NUMBER_INT) { throw invalid(); }
                    result.put(name, parser.getLongValue());
                } else if ("kid".equals(name) || "requestId".equals(name) || "iv".equals(name)
                        || "wrappedKey".equals(name) || "ciphertext".equals(name) || "tag".equals(name)) {
                    if (value != JsonToken.VALUE_STRING) { throw invalid(); }
                    result.put(name, parser.getText());
                } else {
                    throw invalid();
                }
            }
            if (parser.nextToken() != null || result.size() != 8) { throw invalid(); }
            return result;
        }
    }

    private static IllegalArgumentException invalid() { return new IllegalArgumentException("Invalid encrypted request"); }

    private static byte[] readLimited(InputStream in, int max) throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream(Math.min(max, 4096));
        byte[] buffer = new byte[4096];
        for (int n; (n = in.read(buffer)) != -1; ) {
            if (n > max - body.size()) { throw new BodyTooLarge(); }
            body.write(buffer, 0, n);
        }
        return body.toByteArray();
    }

    private static final class BodyTooLarge extends IOException {
        private static final long serialVersionUID = 1L;
    }

    private static final class VerifiedRoute {
        final String path;
        VerifiedRoute(String path) { this.path = path; }
    }

    private static final class VerifiedEnvelope {
        final String requestId;
        final byte[] responseKey;
        final byte[] plaintext;
        VerifiedEnvelope(String requestId, byte[] responseKey, byte[] plaintext) {
            this.requestId = requestId;
            this.responseKey = responseKey;
            this.plaintext = plaintext;
        }
    }
}
