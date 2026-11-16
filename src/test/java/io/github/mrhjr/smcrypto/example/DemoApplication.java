package io.github.mrhjr.smcrypto.example;

import io.github.mrhjr.smcrypto.EncryptedApi;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Import;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/** Local interoperability demo. Not included in the starter JAR. */
@SpringBootConfiguration
@EnableAutoConfiguration
@Import(DemoApplication.Echo.class)
public class DemoApplication {
    public static void main(String[] args) {
        String key = System.getenv("SM_CRYPTO_DEMO_KEY");
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("Set SM_CRYPTO_DEMO_KEY to a fresh demo-only SM2 private scalar");
        }
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("server.address", "127.0.0.1");
        params.put("server.port", "18080");
        params.put("sm-crypto.enabled", true);
        params.put("sm-crypto.exclude-paths[0]", "/demo/plain");
        params.put("sm-crypto.active-kid", "local-demo");
        params.put("sm-crypto.private-keys.local-demo", key);
        SpringApplication app = new SpringApplication(DemoApplication.class);
        app.setDefaultProperties(params);
        app.run(args);
    }

    @RestController
    public static class Echo {
        @EncryptedApi
        @PostMapping("/demo/echo")
        public Map<String, String> echo(@RequestBody Map<String, String> body) {
            return body;
        }

        @EncryptedApi
        @PostMapping("/demo/reject")
        public ResponseEntity<Map<String, String>> reject(@RequestBody Map<String, String> body) {
            return ResponseEntity.unprocessableEntity().body(body);
        }

        @PostMapping("/demo/plain")
        public Map<String, String> plain(@RequestBody Map<String, String> body) { return body; }

        @GetMapping("/demo/plain")
        public Map<String, String> plainGet() { return java.util.Collections.singletonMap("message", "plain GET"); }
    }
}
