package io.github.mrhjr.smcrypto;

import java.security.SecureRandom;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootVersion;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(classes = Boot3AutoConfigurationTest.TestApp.class, properties = {
        "sm-crypto.enabled=true", "sm-crypto.active-kid=boot3-smoke", "sm-crypto.paths[0]=/example/echo"
})
@AutoConfigureMockMvc
class Boot3AutoConfigurationTest {
    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    static class TestApp {}

    @DynamicPropertySource
    static void ephemeralKey(DynamicPropertyRegistry registry) {
        byte[] scalar = new byte[32];
        new SecureRandom().nextBytes(scalar);
        scalar[0] = 1;  // Consistently inside the curve's valid nonzero scalar range.
        String key = Base64.getUrlEncoder().withoutPadding().encodeToString(scalar);
        registry.add("sm-crypto.private-keys.boot3-smoke", () -> key);
    }

    @Autowired
    private MockMvc mvc;

    @Test
    void boot3DiscoversStarterWithoutAnExplicitApplicationImport() throws Exception {
        assertThat(SpringBootVersion.getVersion()).startsWith("3.");
        mvc.perform(get("/crypto/public-key"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.kid").value("boot3-smoke"))
                .andExpect(jsonPath("$.publicKey").isString());
    }
}
