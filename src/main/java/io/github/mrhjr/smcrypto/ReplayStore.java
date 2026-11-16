package io.github.mrhjr.smcrypto;

/**
 * Implement with an atomic insert-if-absent across application instances in production.
 * Only return true once per ID, through the supplied expiry (inclusive). Fail closed if unavailable.
 */
@FunctionalInterface
public interface ReplayStore {
    boolean claim(String requestId, long expiresAtMillis, long nowMillis);
}
