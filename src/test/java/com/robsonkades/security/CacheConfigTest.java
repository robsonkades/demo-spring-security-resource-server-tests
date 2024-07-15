package com.robsonkades.security;

import org.junit.jupiter.api.Test;
import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCacheManager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class CacheConfigTest {

    @Test
    public void testCacheManagerConfiguration() {
        CacheConfig cacheConfig = new CacheConfig();
        CacheManager cacheManager = cacheConfig.cacheManager();

        assertNotNull(cacheManager);

        assertInstanceOf(CaffeineCacheManager.class, cacheManager);

        CaffeineCacheManager caffeineCacheManager = (CaffeineCacheManager) cacheManager;

        assertThat(caffeineCacheManager.getCacheNames())
                .containsExactlyInAnyOrder(
                        "http://localhost:8080/auth/realms/master",
                        "http://localhost:8080/auth/realms/application"
                );
    }
}