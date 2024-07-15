package com.robsonkades.security;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping
public class Resource {

    @GetMapping("/users/me")
    public ResponseEntity<Object> currentUser(@AuthenticationPrincipal Jwt jwt) {
        return ResponseEntity.ok(jwt.getClaims());
    }

    @GetMapping("/tenants")
    public ResponseEntity<Object> tenants() {
        return ResponseEntity.ok("tenants");
    }

    @GetMapping("/customers")
    public ResponseEntity<Object> customers(Authentication authentication) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Object principal = auth.getPrincipal();
        return ResponseEntity.ok("customers");
    }

    @GetMapping("/users/anonymous")
    public ResponseEntity<Object> anonymous() {
        return ResponseEntity.ok("anonymous");
    }
}
