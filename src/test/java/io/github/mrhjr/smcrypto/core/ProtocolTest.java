package io.github.mrhjr.smcrypto.core;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ProtocolTest {
    // Public RFC 8998 Appendix A.1 vector; not deployment key material.
    private static final byte[] KEY = hex("0123456789ABCDEFFEDCBA9876543210");
    private static final byte[] IV = hex("00001234567800000000ABCD");
    private static final byte[] PLAINTEXT = hex(
            "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD"
            + "EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA");
    private static final byte[] AAD = hex("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2");
    private static final byte[] SEALED = hex(
            "17F399F08C67D5EE19D0DC9969C4BB7D5FD46FD3756489069157B282BB200735"
            + "D82710CA5C22F0CCFA7CBF93D496AC15A56834CBCF98C397B4024A2691233B8D"
            + "83DE3541E4C2B58177E065A9BF7B62EC");

    @Test
    void sm4GcmMatchesPublishedVector() {
        assertArrayEquals(SEALED, Protocol.encrypt(KEY, IV, PLAINTEXT, AAD));
        assertArrayEquals(PLAINTEXT, Protocol.decrypt(KEY, IV, SEALED, AAD));
    }

    @Test
    void decryptRejectsTamperedCiphertextAndTag() {
        for (int offset : new int[]{0, SEALED.length - 1}) {
            byte[] tampered = SEALED.clone();
            tampered[offset] ^= 1;
            assertThrows(IllegalArgumentException.class, () -> Protocol.decrypt(KEY, IV, tampered, AAD));
        }
    }

    @Test
    void decryptRejectsSubstitutedAssociatedData() {
        byte[] tampered = AAD.clone();
        tampered[0] ^= 1;
        assertThrows(IllegalArgumentException.class, () -> Protocol.decrypt(KEY, IV, SEALED, tampered));
    }

    @Test
    void rejectsInvalidGcmWidths() {
        assertThrows(IllegalArgumentException.class, () -> Protocol.encrypt(new byte[15], IV, PLAINTEXT, AAD));
        assertThrows(IllegalArgumentException.class, () -> Protocol.encrypt(KEY, new byte[11], PLAINTEXT, AAD));
        assertThrows(IllegalArgumentException.class, () -> Protocol.decrypt(KEY, IV, new byte[15], AAD));
    }

    @Test
    void emitsCanonicalUnpaddedBase64Url() {
        byte[] data = hex("FBFFFF");
        assertEquals("-___", Protocol.encode(data));
        assertArrayEquals(data, Protocol.decode("-___"));
        assertArrayEquals(new byte[0], Protocol.decode(""));
        for (String invalid : new String[]{"+///", "Zg==", "Zh", "Zg\n", "A"}) {
            assertThrows(IllegalArgumentException.class, () -> Protocol.decode(invalid));
        }
    }

    @Test
    void canonicalRequestAadIncludesTheExactEncodedPath() {
        assertArrayEquals(bytes("SMCRYPTO/1\nREQ\nkey-1\nrequest_123\n1700000000\nPOST\n/api/%E4%B8%AD"),
                Protocol.requestAad("key-1", "request_123", 1700000000, "POST", "/api/%E4%B8%AD"));
    }

    @Test
    void canonicalResponseAadBindsResponseStatus() {
        assertArrayEquals(bytes("SMCRYPTO/1\nRESP\nrequest_123\n422"),
                Protocol.responseAad("request_123", 422));
    }

    @Test
    void rejectsAmbiguousOrUnsafeAadComponents() {
        assertThrows(IllegalArgumentException.class, () -> Protocol.requestAad("a\nb", "c", 1, "POST", "/x"));
        assertThrows(IllegalArgumentException.class, () -> Protocol.requestAad("a", "b\rc", 1, "POST", "/x"));
        assertThrows(IllegalArgumentException.class, () -> Protocol.requestAad("a", "b", 1, "post", "/x"));
        assertThrows(IllegalArgumentException.class, () -> Protocol.requestAad("a", "b", 1, "POST", "/x?p=1"));
        assertThrows(IllegalArgumentException.class, () -> Protocol.requestAad("a", "b", 1, "POST", "/x#y"));
        assertThrows(IllegalArgumentException.class, () -> Protocol.requestAad("a", "b", 1, "POST", "relative"));
        assertThrows(IllegalArgumentException.class, () -> Protocol.requestAad("a", "b", -1, "POST", "/x"));
        assertThrows(IllegalArgumentException.class, () -> Protocol.responseAad("x\ny", 200));
        assertThrows(IllegalArgumentException.class, () -> Protocol.responseAad("x", 600));
    }

    @Test
    void derivesRawUncompressedSm2PublicPoint() {
        // d=1 is a public test scalar: its public point is the standard SM2 generator G.
        assertArrayEquals(hex("0432C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
                + "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"),
                Protocol.publicKey(testScalar()));
        assertThrows(IllegalArgumentException.class, () -> Protocol.publicKey(new byte[32]));
        assertThrows(IllegalArgumentException.class, () -> Protocol.publicKey(new byte[31]));
        assertThrows(IllegalArgumentException.class, () -> Protocol.publicKey(
                hex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123")));
    }

    @Test
    void unwrapsAnIndependentlyWrappedOneRequestKeyBundle() throws Exception {
        byte[] bundle = new byte[32];
        new SecureRandom().nextBytes(bundle);
        byte[] wrapped = wrap(bundle, SM2Engine.Mode.C1C3C2);
        assertEquals(129, wrapped.length);
        assertArrayEquals(bundle, Protocol.unwrap(testScalar(), wrapped));
    }

    @Test
    void rejectsWrongSm2WireFormatAndTampering() throws Exception {
        byte[] bundle = new byte[32];
        new SecureRandom().nextBytes(bundle);
        byte[] wrongOrder = wrap(bundle, SM2Engine.Mode.C1C2C3);
        assertThrows(IllegalArgumentException.class, () -> Protocol.unwrap(testScalar(), wrongOrder));
        byte[] correct = wrap(bundle, SM2Engine.Mode.C1C3C2);
        assertThrows(IllegalArgumentException.class, () -> Protocol.unwrap(testScalar(), Arrays.copyOf(correct, 128)));
        byte[] wrongPrefix = correct.clone();
        wrongPrefix[0] = 2;
        assertThrows(IllegalArgumentException.class, () -> Protocol.unwrap(testScalar(), wrongPrefix));
        byte[] wrongPoint = correct.clone();
        Arrays.fill(wrongPoint, 1, 65, (byte) 0);
        assertThrows(IllegalArgumentException.class, () -> Protocol.unwrap(testScalar(), wrongPoint));
        byte[] wrongTag = correct.clone();
        wrongTag[65] ^= 1;
        assertThrows(IllegalArgumentException.class, () -> Protocol.unwrap(testScalar(), wrongTag));
    }

    @Test
    void cryptoCallsDoNotShareMutableCipherState() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            List<Callable<byte[]>> tasks = new ArrayList<>();
            for (int i = 0; i < 24; i++) {
                tasks.add(() -> Protocol.decrypt(KEY, IV, SEALED, AAD));
            }
            for (Future<byte[]> result : pool.invokeAll(tasks)) {
                assertArrayEquals(PLAINTEXT, result.get());
            }
        } finally {
            pool.shutdownNow();
        }
    }

    private static byte[] wrap(byte[] bundle, SM2Engine.Mode mode) throws Exception {
        X9ECParameters curve = GMNamedCurves.getByName("sm2p256v1");
        ECDomainParameters domain = new ECDomainParameters(curve.getCurve(), curve.getG(), curve.getN(),
                curve.getH(), curve.getSeed());
        SM2Engine engine = new SM2Engine(mode);
        engine.init(true, new ParametersWithRandom(
                new ECPublicKeyParameters(curve.getG().multiply(BigInteger.ONE), domain), new SecureRandom()));
        return engine.processBlock(bundle, 0, bundle.length);
    }

    private static byte[] testScalar() {
        byte[] scalar = new byte[32];
        scalar[31] = 1;
        return scalar;
    }

    private static byte[] hex(String value) {
        return Hex.decode(value);
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
