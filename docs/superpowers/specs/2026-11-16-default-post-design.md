# Default protection for POST JSON in v0.2.0

When enabled, the starter protects all POST request bodies and responses in its MVC scope. The new exact-path exclude-paths setting deliberately allows plaintext for listed POST endpoints. The other HTTP methods do not participate. Unsupported POST formats are not a bypass; the host explicitly excludes uploads/forms when needed. GET public-key bootstrap and CORS OPTIONS are unaffected.

Do not reinterpret old opted-in paths as exclusions or silently ignore them when enabling this major behavior change. An explicit annotated POST cannot also be excluded, and non-POST handlers do not require envelopes. Guard unverified protected dispatches, including forwards. Preserve the existing SM2/SM4-GCM wire format, frontend SDK, and existing v0.1.0 binaries. Ship distinct v0.2.0 binaries for the same Boot/JDK pairs.
