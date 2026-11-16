# Spring Boot 3 adapter for the SM crypto starter

Keep the existing Boot 2 javax binaries and package coordinates intact. Add a separate, thin Boot 3 Jakarta servlet starter, with a distinct Maven artifact ID and opt-in auto-configuration via Boot 3's imports file. The new adapter keeps the same endpoints, settings, keys, JSON envelope and frontend SDK. The Boot 2 and Boot 3 variants are alternatives, not dependencies to install together.

Build and test two artifacts using the actual Temurin JDK 17 and JDK 21 with matching classfile targets. Use Spring Boot 3.5.16 as the verified framework baseline; do not infer coverage of every 3.x minor. Test the existing frontend against a running Boot 3 server. Publish Boot 3 jars and SHA256 checksums separately without changing the Boot 2 dist files.
