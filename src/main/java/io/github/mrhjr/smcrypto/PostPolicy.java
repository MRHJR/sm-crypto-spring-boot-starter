package io.github.mrhjr.smcrypto;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/** Shared raw URI policy: exact paths or non-root subtree suffixes; never decode or normalize. */
final class PostPolicy {
    private static final Pattern CANONICAL_PATH = Pattern.compile("/[A-Za-z0-9/_~.-]{0,1023}");
    private final boolean enabled;
    private final Set<String> excluded;
    private final Set<String> excludedPrefixes;

    PostPolicy(CryptoProperties config) {
        this.enabled = config.isEnabled();
        if (enabled && config.getPaths() != null) {
            throw new IllegalArgumentException("sm-crypto.paths is no longer supported. POST is protected by default; "
                    + "remove sm-crypto.paths and configure sm-crypto.exclude-paths for intentionally plaintext POST routes.");
        }
        List<String> paths = config.getExcludePaths();
        Set<String> exact = new HashSet<>();
        Set<String> prefixes = new HashSet<>();
        if (enabled) {
            if (paths == null) { throw invalidExclusions(); }
            for (String rule : paths) {
                if (rule != null && rule.endsWith("/**")) {
                    String prefix = rule.substring(0, rule.length() - 3);
                    if (!validExactPath(prefix) || "/".equals(prefix)) { throw invalidExclusions(); }
                    prefixes.add(prefix);
                } else {
                    if (!validExactPath(rule)) { throw invalidExclusions(); }
                    exact.add(rule);
                }
            }
        }
        this.excluded = Collections.unmodifiableSet(exact);
        this.excludedPrefixes = Collections.unmodifiableSet(prefixes);
    }

    static boolean isPost(String method) { return "POST".equals(method); }

    boolean isExcluded(String path) {
        if (excluded.contains(path)) { return true; }
        if (excludedPrefixes.isEmpty() || !validExactPath(path)) { return false; }
        if (excludedPrefixes.contains(path)) { return true; }
        for (int i = path.indexOf('/', 1); i >= 0; i = path.indexOf('/', i + 1)) {
            if (excludedPrefixes.contains(path.substring(0, i))) { return true; }
        }
        return false;
    }

    private static IllegalArgumentException invalidExclusions() {
        return new IllegalArgumentException("sm-crypto.exclude-paths must contain canonical, exact request URIs "
                + "or a non-root path with a single trailing /**");
    }

    boolean requiresEncryption(String method, String path) {
        return enabled && isPost(method) && !isExcluded(path);
    }

    static boolean validExactPath(String path) {
        if (path == null || !CANONICAL_PATH.matcher(path).matches() || path.contains("//")
                || (path.length() > 1 && path.endsWith("/"))) {
            return false;
        }
        for (String segment : path.split("/")) {
            if (".".equals(segment) || "..".equals(segment)) { return false; }
        }
        return true;
    }
}
