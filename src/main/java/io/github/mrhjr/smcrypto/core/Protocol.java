package io.github.mrhjr.smcrypto.core;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Pattern;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;

/** Byte-level operations for the SMCRYPTO/1 envelope. */
public final class Protocol {
    private static final String PREFIX = "SMCRYPTO/1\n";
    private static final int KEY_BYTES = 16;
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BYTES = 16;
    private static final int BUNDLE_BYTES = 2 * KEY_BYTES;
    private static final int WRAPPED_BYTES = 65 + 32 + BUNDLE_BYTES;
    private static final Pattern TOKEN = Pattern.compile("[A-Za-z0-9_-]{1,128}");
    private static final Pattern METHOD = Pattern.compile("[A-Z]{1,16}");
    private static final Pattern RAW_PATH = Pattern.compile("/[\\x21-\\x7E]*");
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();
    private static final X9ECParameters CURVE = GMNamedCurves.getByName("sm2p256v1");
    private static final ECDomainParameters DOMAIN = new ECDomainParameters(
            CURVE.getCurve(), CURVE.getG(), CURVE.getN(), CURVE.getH(), CURVE.getSeed());

    private Protocol() {
    }

    /** Decodes canonical, unpadded RFC 4648 base64url (including the empty string). */
    public static byte[] decode(String text) {
        if (text == null || text.indexOf('=') >= 0) {
            throw invalid();
        }
        try {
            byte[] bytes = DECODER.decode(text);
            if (ENCODER.encodeToString(bytes).equals(text)) {
                return bytes;
            }
        } catch (IllegalArgumentException malformed) {
            // Do not expose low-level parsing details.
        }
        throw invalid();
    }

    public static String encode(byte[] bytes) {
        if (bytes == null) {
            throw invalid();
        }
        return ENCODER.encodeToString(bytes);
    }

    public static byte[] requestAad(String kid, String requestId, long timestamp, String method, String path) {
        requireToken(kid);
        requireToken(requestId);
        if (timestamp < 0 || method == null || !METHOD.matcher(method).matches()
                || path == null || !RAW_PATH.matcher(path).matches()
                || path.indexOf('?') >= 0 || path.indexOf('#') >= 0 || path.indexOf('\\') >= 0) {
            throw invalid();
        }
        return utf8(PREFIX + "REQ\n" + kid + "\n" + requestId + "\n" + timestamp + "\n" + method + "\n" + path);
    }

    public static byte[] responseAad(String requestId, int status) {
        requireToken(requestId);
        if (status < 100 || status > 599) {
            throw invalid();
        }
        return utf8(PREFIX + "RESP\n" + requestId + "\n" + status);
    }

    /** Returns the SEC 1 uncompressed 65-byte public point (04 || X || Y). */
    public static byte[] publicKey(byte[] privateScalar32) {
        BigInteger scalar = scalar(privateScalar32);
        return new FixedPointCombMultiplier().multiply(DOMAIN.getG(), scalar).getEncoded(false);
    }

    /** Opens a 129-byte raw SM2 C1 || C3 || C2 envelope containing K_req || K_resp. */
    public static byte[] unwrap(byte[] privateScalar32, byte[] wrapped) {
        if (!hasLength(wrapped, WRAPPED_BYTES) || wrapped[0] != 4) {
            throw invalid();
        }
        BigInteger scalar = scalar(privateScalar32);
        try {
            SM2Engine engine = new SM2Engine(SM2Engine.Mode.C1C3C2);
            engine.init(false, new ECPrivateKeyParameters(scalar, DOMAIN));
            byte[] bundle = engine.processBlock(wrapped, 0, wrapped.length);
            if (bundle.length == BUNDLE_BYTES) {
                return bundle;
            }
            Arrays.fill(bundle, (byte) 0);
        } catch (InvalidCipherTextException | IllegalArgumentException malformed) {
            // Treat invalid points, keys and integrity checks identically at this boundary.
        }
        throw invalid();
    }

    /** Seals SM4-GCM bytes as ciphertext || 16-byte tag. Never reuse an IV for a key. */
    public static byte[] encrypt(byte[] key, byte[] iv, byte[] plain, byte[] aad) {
        return gcm(true, key, iv, plain, aad);
    }

    /** Authenticates ciphertext || tag before returning any plaintext. */
    public static byte[] decrypt(byte[] key, byte[] iv, byte[] ciphertextAndTag, byte[] aad) {
        return gcm(false, key, iv, ciphertextAndTag, aad);
    }

    private static byte[] gcm(boolean encrypt, byte[] key, byte[] iv, byte[] input, byte[] aad) {
        if (!hasLength(key, KEY_BYTES) || !hasLength(iv, NONCE_BYTES) || input == null || aad == null
                || (!encrypt && input.length < TAG_BYTES) || (encrypt && input.length > Integer.MAX_VALUE - TAG_BYTES)) {
            throw invalid();
        }
        GCMModeCipher cipher = GCMBlockCipher.newInstance(new SM4Engine());
        cipher.init(encrypt, new AEADParameters(new KeyParameter(key), TAG_BYTES * 8, iv, aad));
        byte[] output = new byte[cipher.getOutputSize(input.length)];
        boolean success = false;
        try {
            int offset = cipher.processBytes(input, 0, input.length, output, 0);
            int length = offset + cipher.doFinal(output, offset);
            if (length != output.length) {
                throw invalid();
            }
            success = true;
            return output;
        } catch (InvalidCipherTextException malformed) {
            throw invalid();
        } finally {
            if (!success) {
                Arrays.fill(output, (byte) 0);
            }
        }
    }

    private static BigInteger scalar(byte[] bytes) {
        if (!hasLength(bytes, 32)) {
            throw invalid();
        }
        BigInteger value = new BigInteger(1, bytes);
        if (value.signum() == 0 || value.compareTo(DOMAIN.getN()) >= 0) {
            throw invalid();
        }
        return value;
    }

    private static boolean hasLength(byte[] value, int length) {
        return value != null && value.length == length;
    }

    private static void requireToken(String value) {
        if (value == null || !TOKEN.matcher(value).matches()) {
            throw invalid();
        }
    }

    private static byte[] utf8(String input) {
        return input.getBytes(StandardCharsets.UTF_8);
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Invalid cryptographic input");
    }
}
