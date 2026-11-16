package io.github.mrhjr.smcrypto;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

/** Shared raw URI policy: never decode, glob, or infer exclusions from content types. */
final class PostPolicy {
    private static final Pattern CANONICAL_PATH = Pattern.compile("/[A-Za-z0-9/_~.-]{0,1023}");
    private final boolean enabled;
    private final Set<String> excluded;

    PostPolicy(CryptoProperties config) {
        this.enabled = config.isEnabled();
        if (enabled && config.getPaths() != null) {
            throw new IllegalArgumentException("sm-crypto.paths is no longer supported. POST is protected by default; "
                    + "remove sm-crypto.paths and configure sm-crypto.exclude-paths for intentionally plaintext POST routes.");
        }
        List<String> paths = config.getExcludePaths();
        if (enabled && (paths == null || paths.stream().anyMatch(p -> !validExactPath(p)))) {
            throw new IllegalArgumentException("sm-crypto.exclude-paths must contain canonical, exact request URIs");
        }
        this.excluded = enabled ? Collections.unmodifiableSet(new HashSet<>(paths)) : Collections.emptySet();
    }

    static boolean isPost(String method) { return "POST".equals(method); }

    boolean isExcluded(String path) { return excluded.contains(path); }

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
