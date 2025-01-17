package com.robsonkades.security;

import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

@Configuration
@EnableCaching
public class CacheConfig {

    @Bean
    public CacheManager cacheManager() {
        CaffeineCacheManager cacheManager = new CaffeineCacheManager("http://localhost:8080/auth/realms/master", "http://localhost:8080/auth/realms/application");
        cacheManager.setCaffeine(Caffeine.newBuilder()
                .initialCapacity(200)
                .expireAfterAccess(Duration.ofDays(30))
                .maximumSize(500));
        return cacheManager;
    }
}
