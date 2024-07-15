package com.robsonkades.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.cache.CacheManager;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;

import java.util.HashMap;
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest
@ContextConfiguration(classes = {SecurityConfig.class, TestSecurityConfig.class})
public class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private CacheManager cacheManager;

    @Test
    void whenAdminAccessAdminEndpoint_thenOk() throws Exception {
        String token = FakeJwtGenerator.generateToken("test-client", List.of("INVALID"));
        mockMvc.perform(get("/admin-endpoint")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.message").value("Access Denied"));
    }

    @Test
    void whenAdminAccessAdminEndpoint_thenOkNuul() throws Exception {
        String token = FakeJwtGenerator.generateToken(new HashMap<>());
        mockMvc.perform(get("/admin-endpoint")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\", error_description=\"An error occurred while attempting to decode the Jwt: The token has no azp claim\", error_uri=\"https://tools.ietf.org/html/rfc6750#section-3.1\""));
    }
}