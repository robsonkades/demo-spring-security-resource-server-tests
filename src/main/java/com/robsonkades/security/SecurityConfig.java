package com.robsonkades.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecurityConfig.class);

    private final JwtDecoderService jwtDecoderService;

    public SecurityConfig(final JwtDecoderService jwtDecoderService) {
        this.jwtDecoderService = jwtDecoderService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable);
        http.httpBasic(AbstractHttpConfigurer::disable);

        http.authorizeHttpRequests(registry -> registry.requestMatchers(new AntPathRequestMatcher("/users/anonymous")).permitAll());

        http.authorizeHttpRequests(registry -> registry.requestMatchers(new AntPathRequestMatcher("/admin-endpoint/**")).hasRole("ADMIN").requestMatchers(new AntPathRequestMatcher("/customers/**")).hasAnyRole("ADMIN", "USER", "VIEW-PROFILE").anyRequest().authenticated());

        http.oauth2ResourceServer(oauth2 -> oauth2.authenticationManagerResolver(authenticationManagerResolver()));

        http.exceptionHandling(exceptionHandling -> exceptionHandling
                .authenticationEntryPoint(authenticationEntryPoint())
                .accessDeniedHandler(accessDeniedHandler()));
        return http.build();
    }

    @Bean
    public AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver() {
        Stream<String> realms = Stream.of("http://fake-issuer.com");
        Map<String, AuthenticationManager> authenticationManagers = realms.collect(Collectors.toMap(issuer -> issuer, this::createAuthenticationManager));
        return new JwtIssuerAuthenticationManagerResolver(authenticationManagers::get);
    }

    private AuthenticationManager createAuthenticationManager(String issuer) {
        LOGGER.info("Creating AuthenticationManager for issuer: {}", issuer);
        NimbusJwtDecoder jwtDecoder = jwtDecoderService.getJwtDecoder(issuer);
        JwtAuthenticationProvider authenticationProvider = new JwtAuthenticationProvider(jwtDecoder);
        authenticationProvider.setJwtAuthenticationConverter(jwtAuthenticationConverter());

        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuer);
        OAuth2TokenValidator<Jwt> withAudience = new DelegatingOAuth2TokenValidator<>(withIssuer, new DynamicAudienceValidator());

        jwtDecoder.setJwtValidator(withAudience);

        return authenticationProvider::authenticate;
    }

    protected JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            String azp = jwt.getClaimAsString("azp");
            LOGGER.debug("Extracting roles for client (azp): {}", azp);

            Set<String> allRoles = new HashSet<>();

            Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
            if (realmAccess != null) {
                List<String> realmRoles = (List<String>) realmAccess.getOrDefault("roles", Collections.emptyList());
                allRoles.addAll(realmRoles);
            }

            Map<String, Object> resourceAccess = jwt.getClaimAsMap("resource_access");
            if (resourceAccess != null && azp != null) {
                Map<String, Object> clientAccess = (Map<String, Object>) resourceAccess.get(azp);
                if (clientAccess != null) {
                    List<String> clientRoles = (List<String>) clientAccess.getOrDefault("roles", Collections.emptyList());
                    allRoles.addAll(clientRoles);
                }
            }

            return allRoles.stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase())).collect(Collectors.toList());
        });
        return converter;
    }

    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, accessDeniedException) -> {
            response.setContentType("application/json");
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);

            String jsonResponse = String.format("{\"status\": \"%s\", \"message\": \"%s\"}", HttpServletResponse.SC_FORBIDDEN, accessDeniedException.getMessage());
            response.getOutputStream().println(jsonResponse);
        };
    }

    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return (request, response, authException) -> {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);

            String errorMessage = "Authentication failed";
            if (authException instanceof OAuth2AuthenticationException oAuth2AuthenticationException) {
                OAuth2Error error = oAuth2AuthenticationException.getError();
                errorMessage = error.getDescription();
            }

            String clientId = "unknown";
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth instanceof JwtAuthenticationToken jwtAuthenticationToken) {
                clientId = jwtAuthenticationToken.getToken().getClaimAsString("azp");
            }

            String jsonResponse = String.format("{\"status\": \"%s\", \"message\": \"%s\", \"client_id\": \"%s\"}", HttpServletResponse.SC_UNAUTHORIZED, errorMessage, clientId);
            response.getWriter().write(jsonResponse);
        };
    }

    private static class DynamicAudienceValidator implements OAuth2TokenValidator<Jwt> {
        @Override
        public OAuth2TokenValidatorResult validate(Jwt jwt) {
            String azp = jwt.getClaimAsString("azp");
            if (azp == null || azp.isEmpty()) {
                return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "The token has no azp claim", null));
            }
//            if (!jwt.getAudience().contains(azp)) {
//                return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "The token audience does not match the azp claim", null));
//            }
            return OAuth2TokenValidatorResult.success();
        }
    }
}
