package com.robsonkades.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Import(TestSecurityConfig.class)
public class ApiIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    public void testAdminEndpoint() throws Exception {
        String token = FakeJwtGenerator.generateToken("test-client", List.of("ADMIN"));

        mockMvc.perform(get("/admin-endpoint")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.message").value("Hello, World!"));
    }

    @Test
    public void testAdminEndpoint2() throws Exception {
        String token = FakeJwtGenerator.generateToken("test-client", List.of("INVALID"));

        mockMvc.perform(get("/admin-endpoint")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.message").value("Access Denied"));
    }

    @Test
    public void testAdminEndpoint3() throws Exception {

        mockMvc.perform(get("/admin-endpoint"))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentType("application/json"))
                .andExpect(jsonPath("$.message").value("Authentication failed"));
    }

    @Test
    public void testAdminEndpoint4() throws Exception {
        mockMvc.perform(get("/admin-endpoint")
                        .header("Authorization", "Bearer INVALID"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().string(HttpHeaders.WWW_AUTHENTICATE, "Bearer error=\"invalid_token\", error_description=\"Invalid JWT serialization: Missing dot delimiter(s)\", error_uri=\"https://tools.ietf.org/html/rfc6750#section-3.1\""));
    }

}
