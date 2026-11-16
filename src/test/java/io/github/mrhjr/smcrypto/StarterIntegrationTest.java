package io.github.mrhjr.smcrypto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.servlet.DispatcherType;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(classes = StarterIntegrationTest.TestApp.class)
@AutoConfigureMockMvc
class StarterIntegrationTest {
    private static final String PATH = "/orders";
    private static final String KID = "integration-key";
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final X9ECParameters CURVE = GMNamedCurves.getByName("sm2p256v1");
    private static final ECDomainParameters DOMAIN = new ECDomainParameters(CURVE.getCurve(), CURVE.getG(),
            CURVE.getN(), CURVE.getH());
    private static final byte[] SCALAR;
    static {
        do {
            final byte[] candidate = random(32);
            BigInteger value = new BigInteger(1, candidate);
            if (value.signum() > 0 && value.compareTo(CURVE.getN()) < 0) {
                SCALAR = candidate;
                break;
            }
        } while (true);
    }

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;

    @DynamicPropertySource
    static void config(DynamicPropertyRegistry r) {
        r.add("sm-crypto.enabled", () -> "true");
        r.add("sm-crypto.active-kid", () -> KID);
        r.add("sm-crypto.private-keys." + KID, () -> encode(SCALAR));
        r.add("sm-crypto.paths[0]", () -> PATH);
        r.add("sm-crypto.paths[1]", () -> "/orders/error");
        r.add("sm-crypto.max-body-bytes", () -> "4096");
    }

    @Test void bootPublishesOnlyTheActivePublicKey() throws Exception {
        mvc.perform(get("/crypto/public-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.kid").value(KID))
                .andExpect(jsonPath("$.publicKey").value(encode(
                        CURVE.getG().multiply(new BigInteger(1, SCALAR)).getEncoded(false))))
                .andExpect(jsonPath("$.privateKey").doesNotExist());
    }

    @Test void decryptsJsonAndEncryptsControllerDto() throws Exception {
        Packet packet = make(PATH, System.currentTimeMillis(), "{\"name\":\"测试\"}");
        MvcResult result = send(PATH, packet.wire()).andExpect(status().isOk()).andReturn();
        assertFalse(result.getResponse().getContentAsString().contains("测试"));
        assertEquals("测试", open(packet, result).path("name").asText());
    }

    @Test void honorsHttpStatusAndEncryptsBusinessError() throws Exception {
        String path = "/orders/error";
        Packet packet = make(path, System.currentTimeMillis(), "{\"name\":\"hi\"}");
        MvcResult result = send(path, packet.wire()).andExpect(status().isUnprocessableEntity()).andReturn();
        assertEquals("invalid-order", open(packet, result).path("code").asText());
    }

    @Test void plaintextNeverReachesProtectedController() throws Exception {
        send(PATH, "{\"name\":\"not-encrypted\"}")
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("INVALID_ENCRYPTED_REQUEST"));
    }

    @Test void alternateRouteOfMarkedControllerDoesNotBypassEncryption() throws Exception {
        send("/alternate-orders", "{\"name\":\"not-encrypted\"}")
                .andExpect(status().isBadRequest());
    }

    @Test void unrelatedPlainJsonEndpointRemainsPlain() throws Exception {
        send("/plain", "{\"name\":\"still-plain\"}").andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("still-plain"));
    }

    @Test void changedTagIsRejectedWithoutConsumingRequestId() throws Exception {
        Packet packet = make(PATH, System.currentTimeMillis(), "{\"name\":\"hi\"}");
        String correctTag = (String) packet.wire.get("tag");
        byte[] changed = decode(correctTag);
        changed[0] ^= 1;
        packet.wire.put("tag", encode(changed));
        send(PATH, packet.wire()).andExpect(status().isBadRequest());
        packet.wire.put("tag", correctTag);
        send(PATH, packet.wire()).andExpect(status().isOk());
    }

    @Test void identicalEnvelopeIsAcceptedAtMostOnce() throws Exception {
        Packet packet = make(PATH, System.currentTimeMillis(), "{\"name\":\"hi\"}");
        String wire = packet.wire();
        send(PATH, wire).andExpect(status().isOk());
        send(PATH, wire).andExpect(status().isBadRequest());
    }

    @Test void requestCannotBeMovedToAnotherProtectedPath() throws Exception {
        Packet packet = make(PATH, System.currentTimeMillis(), "{\"name\":\"hi\"}");
        send("/orders/error", packet.wire()).andExpect(status().isBadRequest());
    }

    @Test void staleEnvelopesAndQueriesAreRejected() throws Exception {
        Packet packet = make(PATH, System.currentTimeMillis() - 600_000, "{\"name\":\"hi\"}");
        send(PATH, packet.wire()).andExpect(status().isBadRequest());
        Packet fresh = make(PATH, System.currentTimeMillis(), "{\"name\":\"hi\"}");
        mvc.perform(post(PATH).queryParam("mode", "other").contentType(MediaType.APPLICATION_JSON)
                .content(fresh.wire())).andExpect(status().isBadRequest());
    }

    @Test void duplicateAndTrailingEnvelopeFieldsAreRejected() throws Exception {
        Packet packet = make(PATH, System.currentTimeMillis(), "{\"name\":\"hi\"}");
        String wire = packet.wire();
        send(PATH, wire.replaceFirst("\\{", "{\"version\":1,")).andExpect(status().isBadRequest());
        send(PATH, wire + "{}").andExpect(status().isBadRequest());
        send(PATH, wire.replace("\"version\":1", "\"version\":[1]")).andExpect(status().isBadRequest());
        send(PATH, wire).andExpect(status().isOk());
    }

    @Test void forwardedDispatchDoesNotAuthenticateAsANewWireRequest() throws Exception {
        Packet packet = make(PATH, System.currentTimeMillis(), "{\"name\":\"hi\"}");
        mvc.perform(post(PATH).with(request -> {
            request.setDispatcherType(DispatcherType.FORWARD);
            return request;
        }).contentType(MediaType.APPLICATION_JSON).content(packet.wire()))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("INVALID_ENCRYPTED_REQUEST"));
    }

    @Test void refusesOversizedRequestBeforeUnwrappingKeys() throws Exception {
        send(PATH, new String(new char[4097]).replace('\0', 'a')).andExpect(status().isPayloadTooLarge());
    }

    @Test void replayStoreRetainsThroughExpiryAndFailsWhenFull() {
        ReplayStore replay = new InMemoryReplayStore(1);
        assertTrue(replay.claim("first", 10, 0));
        assertFalse(replay.claim("first", 20, 10));
        assertFalse(replay.claim("second", 20, 10));
        assertTrue(replay.claim("second", 20, 11));
        assertFalse(replay.claim("first", 19, 11));
    }

    @Test void missingConfigurationFailsClosed() {
        assertThrows(IllegalArgumentException.class, () -> new KeyRing("missing", java.util.Collections.emptyMap()));
    }

    private org.springframework.test.web.servlet.ResultActions send(String route, String body) throws Exception {
        return mvc.perform(post(route).contentType(MediaType.APPLICATION_JSON).content(body));
    }

    private Packet make(String path, long time, String body) throws Exception {
        byte[] keys = random(32);
        byte[] iv = random(12);
        String id = encode(random(16));
        Map<String,Object> wire = new LinkedHashMap<>();
        wire.put("version", 1);
        wire.put("kid", KID);
        wire.put("requestId", id);
        wire.put("timestamp", time);
        SM2Engine sm2 = new SM2Engine(SM2Engine.Mode.C1C3C2);
        sm2.init(true, new ParametersWithRandom(
                new ECPublicKeyParameters(CURVE.getG().multiply(new BigInteger(1, SCALAR)), DOMAIN), RANDOM));
        wire.put("wrappedKey", encode(sm2.processBlock(keys, 0, keys.length)));
        wire.put("iv", encode(iv));
        byte[] output = gcm(true, Arrays.copyOf(keys, 16), iv, bytes(body),
                "SMCRYPTO/1\nREQ\n" + KID + "\n" + id + "\n" + time + "\nPOST\n" + path);
        wire.put("ciphertext", encode(Arrays.copyOf(output, output.length - 16)));
        wire.put("tag", encode(Arrays.copyOfRange(output, output.length - 16, output.length)));
        return new Packet(id, Arrays.copyOfRange(keys, 16, 32), wire);
    }

    private JsonNode open(Packet packet, MvcResult result) throws Exception {
        JsonNode wire = json.readTree(result.getResponse().getContentAsByteArray());
        assertEquals(1, wire.path("version").asInt());
        assertEquals(packet.id, wire.path("requestId").asText());
        byte[] ct = decode(wire.path("ciphertext").asText());
        byte[] tag = decode(wire.path("tag").asText());
        byte[] sealed = Arrays.copyOf(ct, ct.length + tag.length);
        System.arraycopy(tag, 0, sealed, ct.length, tag.length);
        return json.readTree(gcm(false, packet.responseKey, decode(wire.path("iv").asText()), sealed,
                "SMCRYPTO/1\nRESP\n" + packet.id + "\n" + result.getResponse().getStatus()));
    }

    private static byte[] gcm(boolean encryption, byte[] key, byte[] iv, byte[] data, String aad) throws Exception {
        GCMBlockCipher cipher = new GCMBlockCipher(new SM4Engine());
        cipher.init(encryption, new AEADParameters(new KeyParameter(key), 128, iv, bytes(aad)));
        byte[] output = new byte[cipher.getOutputSize(data.length)];
        int n = cipher.processBytes(data, 0, data.length, output, 0);
        return Arrays.copyOf(output, n + cipher.doFinal(output, n));
    }

    private static byte[] random(int n) { byte[] data = new byte[n]; RANDOM.nextBytes(data); return data; }
    private static byte[] bytes(String text) { return text.getBytes(StandardCharsets.UTF_8); }
    private static String encode(byte[] data) { return Base64.getUrlEncoder().withoutPadding().encodeToString(data); }
    private static byte[] decode(String value) { return Base64.getUrlDecoder().decode(value); }

    private class Packet {
        final String id;
        final byte[] responseKey;
        final Map<String, Object> wire;
        Packet(String id, byte[] responseKey, Map<String, Object> wire) {
            this.id = id;
            this.responseKey = responseKey;
            this.wire = wire;
        }
        String wire() throws Exception { return json.writeValueAsString(wire); }
    }

    @Configuration
    @EnableAutoConfiguration
    @Import(Orders.class)
    static class TestApp {}

    @RestController
    static class Orders {
        @EncryptedApi
        @PostMapping(value = {PATH, "/alternate-orders"}, produces = MediaType.APPLICATION_JSON_VALUE)
        Map<String,String> create(@RequestBody Map<String,String> body) { return body; }

        @EncryptedApi
        @PostMapping(value = "/orders/error", produces = MediaType.APPLICATION_JSON_VALUE)
        ResponseEntity<Map<String,String>> error(@RequestBody Map<String,String> body) {
            return ResponseEntity.unprocessableEntity().body(java.util.Collections.singletonMap("code", "invalid-order"));
        }

        @PostMapping("/plain")
        Map<String,String> plain(@RequestBody Map<String,String> body) { return body; }
    }
}
