package io.github.mrhjr.smcrypto;

import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.servlet.DispatcherType;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.MediaType;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.function.RequestPredicates;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerResponse;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass(DispatcherServlet.class)
@EnableConfigurationProperties(CryptoProperties.class)
public class SmCryptoAutoConfiguration {
    @Bean
    PostPolicy smCryptoPostPolicy(CryptoProperties properties) {
        return new PostPolicy(properties);
    }

    // Keep the marker fail-closed even when the engine is disabled.
    @Bean
    WebMvcConfigurer smCryptoGuardConfigurer(PostPolicy policy) {
        return new WebMvcConfigurer() {
            @Override public void addInterceptors(InterceptorRegistry registry) {
                registry.addInterceptor(new EncryptedApiGuard(policy)).order(Ordered.HIGHEST_PRECEDENCE);
            }
        };
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(prefix = "sm-crypto", name = "enabled", havingValue = "true")
    static class Enabled {
        @Bean
        KeyRing smCryptoKeyRing(CryptoProperties properties) {
            return new KeyRing(properties.getActiveKid(), properties.getPrivateKeys());
        }

        @Bean
        @ConditionalOnMissingBean(ReplayStore.class)
        ReplayStore smCryptoReplayStore(CryptoProperties properties) {
            return new InMemoryReplayStore(properties.getReplayCapacity());
        }

        @Bean
        RouterFunction<ServerResponse> smCryptoPublicKeyRoute(KeyRing keys) {
            return RouterFunctions.route(RequestPredicates.GET("/crypto/public-key"), request -> {
                Map<String, String> publicKey = new LinkedHashMap<>();
                publicKey.put("kid", keys.kid());
                publicKey.put("publicKey", keys.publicKey());
                return ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
                        .header("Cache-Control", "no-store").body(publicKey);
            });
        }

        @Bean
        FilterRegistrationBean<CryptoFilter> smCryptoFilterRegistration(CryptoProperties properties,
                PostPolicy policy, KeyRing keys, ReplayStore replayStore) {
            FilterRegistrationBean<CryptoFilter> filter =
                    new FilterRegistrationBean<>(new CryptoFilter(properties, policy, keys, replayStore));
            filter.setName("smCryptoFilter");
            filter.setDispatcherTypes(EnumSet.of(DispatcherType.REQUEST));
            filter.setAsyncSupported(true);
            filter.addUrlPatterns("/*");
            // Spring Security (if installed) keeps supplying authentication and authorization.
            filter.setOrder(Ordered.LOWEST_PRECEDENCE - 10);
            return filter;
        }
    }
}
