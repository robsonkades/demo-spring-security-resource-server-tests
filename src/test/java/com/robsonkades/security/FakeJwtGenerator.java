package com.robsonkades.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class FakeJwtGenerator {

    public static final String SECRET = "357638792F423F4428472B4B6250655368566D597133743677397A2443264629";

    private static final String ISSUER = "http://fake-issuer.com";

    public static String generateToken(String clientId, List<String> roles) {

        return Jwts.builder().subject("fake-subject").issuer(ISSUER)
                .claim("azp", clientId)
                .claim("realm_access", Map.of("roles", roles))
                .claim("resource_access", Map.of(clientId, Map.of("roles", roles)))
                .issuedAt(new Date()).expiration(new Date(System.currentTimeMillis() + 3600000)) // 1 hour
                .signWith(getSignKey(), Jwts.SIG.HS256)
                .compact();
    }

    public static String generateToken(Map<String, ?> claims) {
        return Jwts.builder().subject("fake-subject").issuer(ISSUER)
                .claims(claims)
                .issuedAt(new Date()).expiration(new Date(System.currentTimeMillis() + 3600000)) // 1 hour
                .signWith(getSignKey(), Jwts.SIG.HS256)
                .compact();
    }

    public static SecretKey getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public static String getIssuer() {
        return ISSUER;
    }
}
