package io.github.mrhjr.smcrypto;

import io.github.mrhjr.smcrypto.core.Protocol;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

final class KeyRing {
    static final Pattern KID = Pattern.compile("[A-Za-z0-9_-]{1,64}");
    private final String activeKid;
    private final Map<String, byte[]> keys;
    private final String publicKey;

    KeyRing(String activeKid, Map<String, String> values) {
        if (activeKid == null || !KID.matcher(activeKid).matches() || values == null
                || !values.containsKey(activeKid)) {
            throw new IllegalArgumentException("sm-crypto.active-kid must name a configured private key");
        }
        Map<String, byte[]> parsed = new HashMap<>();
        String activePublicKey = null;
        for (Map.Entry<String, String> entry : values.entrySet()) {
            if (entry.getKey() == null || !KID.matcher(entry.getKey()).matches()) {
                throw new IllegalArgumentException("sm-crypto contains an invalid key ID");
            }
            try {
                if (entry.getValue() == null || entry.getValue().length() != 43) {
                    throw new IllegalArgumentException("private key length");
                }
                byte[] privateKey = Protocol.decode(entry.getValue());
                byte[] derivedPublicKey = Protocol.publicKey(privateKey);
                if (activeKid.equals(entry.getKey())) {
                    activePublicKey = Protocol.encode(derivedPublicKey);
                }
                parsed.put(entry.getKey(), privateKey);
            } catch (IllegalArgumentException e) {
                // Never add the configuration value (even as a nested exception) to diagnostic output.
                throw new IllegalArgumentException("sm-crypto contains an invalid private key");
            }
        }
        this.activeKid = activeKid;
        this.keys = Collections.unmodifiableMap(parsed);
        this.publicKey = activePublicKey;
    }

    byte[] unwrap(String kid, byte[] envelope) {
        byte[] privateKey = keys.get(kid);
        if (privateKey == null) {
            throw new IllegalArgumentException("Unknown key ID");
        }
        return Protocol.unwrap(privateKey, envelope);
    }

    String kid() { return activeKid; }
    String publicKey() { return publicKey; }
}
