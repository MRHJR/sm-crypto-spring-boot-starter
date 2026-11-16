package io.github.mrhjr.smcrypto;

import java.util.Arrays;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class PostPolicyTest {
    @Test void matchCanonicalParentAndDescendantsOnly() {
        PostPolicy policy = policy("/api/public/**", "/api/one", "/");
        assertTrue(policy.isExcluded("/api/public"));
        assertTrue(policy.isExcluded("/api/public/search"));
        assertTrue(policy.isExcluded("/api/public/nested/search"));
        assertTrue(policy.isExcluded("/api/one"));
        assertTrue(policy.isExcluded("/"));
        assertFalse(policy.isExcluded("/api"));
        assertFalse(policy.isExcluded("/api/publicity"));
        assertFalse(policy.isExcluded("/api/public-v2"));
        assertFalse(policy.isExcluded("/api/one/child"));
        assertFalse(policy.requiresEncryption("GET", "/api/private"));
        assertTrue(policy.requiresEncryption("POST", "/api/private"));
    }

    @Test void neverExemptNonCanonicalRawRequests() {
        PostPolicy policy = policy("/api/public/**");
        for (String path : Arrays.asList("/api/public/", "/api/public/search/", "/api/public//search",
                "/api/public/../private", "/api/public/./search", "/api/public/%73earch",
                "/api/public/encoded%2Fslash", "/api/public/search;v=1", "/api/public/search?mode=1")) {
            assertFalse(policy.isExcluded(path), path);
            assertTrue(policy.requiresEncryption("POST", path), path);
        }
        assertFalse(policy.isExcluded(null));
    }

    @Test void rejectsMalformedAndRootWideRules() {
        for (String rule : Arrays.asList("/**", "/api/*", "/api/public/*", "/api/**/public",
                "/api/public/**/**", "/api/public/***", "/api/public//**", "/api/../**", "/api/%70ublic/**",
                "/api/public;v=1/**", "/api/public/**/", "api/public/**", null)) {
            IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> policy(rule),
                    String.valueOf(rule));
            assertTrue(ex.getMessage().contains("sm-crypto.exclude-paths"));
        }
    }

    private static PostPolicy policy(String... paths) {
        CryptoProperties properties = new CryptoProperties();
        properties.setEnabled(true);
        properties.setExcludePaths(Arrays.asList(paths));
        return new PostPolicy(properties);
    }
}
