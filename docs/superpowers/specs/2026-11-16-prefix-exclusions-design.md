# Prefix exemptions for POST encryption

Add one explicit pattern form to sm-crypto.exclude-paths: a non-root canonical path followed by /**. Such a rule exempts the prefix path itself and its descendants on path-segment boundaries. Exact rules are unchanged. Wildcards elsewhere, global /**, and noncanonical input are not interpreted as exemptions. Never normalize or URL-decode a route to grant an exemption.

POST remains the only protected HTTP method. An explicitly marked @EncryptedApi POST still fails closed if it conflicts with an exclusion. Preserve Spring auth, default protection, framework variants, and v1 wire format. Publish six 0.3.0 builds without overwriting old jars.
