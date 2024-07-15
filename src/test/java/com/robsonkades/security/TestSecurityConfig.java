package com.robsonkades.security;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.cache.CacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

@TestConfiguration
public class TestSecurityConfig {

    private final CacheManager cacheManager;

    public TestSecurityConfig(final CacheManager cacheManager) {
        this.cacheManager = cacheManager;
    }

    @Bean
    @Primary
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withSecretKey(FakeJwtGenerator.getSignKey()).build();
    }

    @Bean
    @Primary
    public JwtDecoderService jwtDecoderService() {
        return new JwtDecoderService(cacheManager) {
            @Override
            public NimbusJwtDecoder getJwtDecoder(String issuer) {
                return NimbusJwtDecoder.withSecretKey(FakeJwtGenerator.getSignKey()).build();
            }
        };
    }
}
