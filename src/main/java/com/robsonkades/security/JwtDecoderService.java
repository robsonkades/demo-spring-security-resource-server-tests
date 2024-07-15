package com.robsonkades.security;

import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;

import java.util.Objects;

@Component
public class JwtDecoderService {

    private final CacheManager cacheManager;

    public JwtDecoderService(CacheManager cacheManager) {
        this.cacheManager = cacheManager;
    }

    public NimbusJwtDecoder getJwtDecoder(String issuer) {
        Cache cache = cacheManager.getCache(issuer);

        Objects.requireNonNull(cache, "Cache Manager -> jwtDecoders is required");

        Cache.ValueWrapper valueWrapper = cache.get(issuer);
        if (valueWrapper == null || valueWrapper.get() == null) {
            NimbusJwtDecoder decoder = createDecoder(issuer);
            cache.put(issuer, decoder);
            return decoder;
        }
        return (NimbusJwtDecoder) valueWrapper.get();
    }

    private NimbusJwtDecoder createDecoder(String issuer) {

        return NimbusJwtDecoder.withJwkSetUri(issuer).jwsAlgorithm(SignatureAlgorithm.RS256).build();
    }
}
