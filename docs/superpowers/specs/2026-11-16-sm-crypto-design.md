# SM2 + SM4-GCM API encryption v1

Use a separate private repository for an opt-in Spring MVC starter and a browser client. HTTPS, authentication and authorization remain mandatory. The application deliberately enables only exact POST JSON endpoint paths. Do not implement a new cipher or store real keys in the repository.

The client obtains the active SM2 public key and its key ID over a trusted HTTPS channel, generates two independent SM4 keys for each request, wraps the pair with SM2 and encrypts the request body with SM4-GCM. The server verifies the request envelope and rejects stale and repeated requests before invoking application code. It encrypts JSON responses under the second key. The client accepts a business response only after authentication of the response envelope. See README for encoding, transport limitations and key rotation.

Publish four artifacts compiled and tested independently on JDK 8/11/17/21 with bytecode target matching the JDK. Boot 2.x and Boot 3.x use different servlet namespaces; v1 targets Boot 2.x only. Verify compatibility separately with Boot 2.6.3 on JDK 8.
