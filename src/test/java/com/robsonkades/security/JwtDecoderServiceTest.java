package com.robsonkades.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class JwtDecoderServiceTest {

    @Mock
    private CacheManager cacheManager;

    @Mock
    private Cache cache;

    @Mock
    private Cache.ValueWrapper valueWrapper;

    @InjectMocks
    private JwtDecoderService jwtDecoderService;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    public void testGetJwtDecoder_CacheIsNull() {
        String issuer = "http://example.com";
        when(cacheManager.getCache(issuer)).thenReturn(null);

        Exception exception = assertThrows(NullPointerException.class, () -> {
            jwtDecoderService.getJwtDecoder(issuer);
        });

        assertTrue(exception.getMessage().contains("Cache Manager -> jwtDecoders is required"));
    }

    @Test
    public void testGetJwtDecoder_ValueWrapperIsNull() {
        String issuer = "http://example.com";
        when(cacheManager.getCache(issuer)).thenReturn(cache);
        when(cache.get(issuer)).thenReturn(null);

        NimbusJwtDecoder decoder = jwtDecoderService.getJwtDecoder(issuer);

        assertNotNull(decoder);
        verify(cache).put(eq(issuer), any(NimbusJwtDecoder.class));
    }

    @Test
    public void testGetJwtDecoder_ValueWrapperGetIsNull() {
        String issuer = "http://example.com";
        when(cacheManager.getCache(issuer)).thenReturn(cache);
        when(cache.get(issuer)).thenReturn(valueWrapper);
        when(valueWrapper.get()).thenReturn(null);

        NimbusJwtDecoder decoder = jwtDecoderService.getJwtDecoder(issuer);

        assertNotNull(decoder);
        verify(cache).put(eq(issuer), any(NimbusJwtDecoder.class));
    }

    @Test
    public void testGetJwtDecoder_ValueWrapperGetIsNotNull() {
        String issuer = "http://example.com";
        NimbusJwtDecoder mockDecoder = mock(NimbusJwtDecoder.class);
        when(cacheManager.getCache(issuer)).thenReturn(cache);
        when(cache.get(issuer)).thenReturn(valueWrapper);
        when(valueWrapper.get()).thenReturn(mockDecoder);

        NimbusJwtDecoder decoder = jwtDecoderService.getJwtDecoder(issuer);

        assertNotNull(decoder);
        assertEquals(mockDecoder, decoder);
        verify(cache, never()).put(anyString(), any(NimbusJwtDecoder.class));
    }
}