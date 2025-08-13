package com.flycatch.authcore.util;

import com.flycatch.authcore.config.AuthCoreConfig;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtil {

    private final AuthCoreConfig.Jwt jwtConfig;
    private SecretKey cachedKey;

    public JwtUtil(AuthCoreConfig authCoreConfig) {
        this.jwtConfig = authCoreConfig.getJwt();
    }

    @PostConstruct
    public void validateConfig() {
        if (jwtConfig.isEnabled()) {
            if (jwtConfig.getSecret() == null || jwtConfig.getSecret().isBlank()) {
                throw new IllegalStateException("JWT is enabled but secret is missing in configuration.");
            }
            try {
                byte[] decoded = Base64.getDecoder().decode(jwtConfig.getSecret());
                if (decoded.length < 32) {
                    throw new IllegalArgumentException("JWT secret must be at least 256 bits (32 bytes) when base64 decoded.");
                }
                this.cachedKey = Keys.hmacShaKeyFor(decoded);
            } catch (IllegalArgumentException e) {
                throw new IllegalStateException("JWT secret must be valid Base64 and at least 256 bits: " + e.getMessage(), e);
            }
        }
    }

    public String generateAccessToken(String username, Map<String, Object> claims) {
        ensureJwtEnabled();
        return generateToken(username, jwtConfig.getAccessTokenExpiration(), claims);
    }

    public String generateRefreshToken(String username) {
        ensureJwtEnabled();
        return generateToken(username, jwtConfig.getRefreshTokenExpiration(), new HashMap<>());
    }

    private String generateToken(String username, long expirationTime, Map<String, Object> claims) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(cachedKey, SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean validateToken(String token, String username) {
        ensureJwtEnabled();
        final String extractedUsername = extractUsername(token);
        return extractedUsername.equals(username) && !isTokenExpired(token);
    }

    public String extractUsername(String token) {
        ensureJwtEnabled();
        return extractClaim(token, Claims::getSubject);
    }

    public Map<String, Object> extractAllClaimsAsMap(String token) {
        ensureJwtEnabled();
        return new HashMap<>(extractAllClaims(token));
    }

    public Date extractExpiration(String token) {
        ensureJwtEnabled();
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        ensureJwtEnabled();
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public Claims extractAllClaims(String token) {
        ensureJwtEnabled();
        JwtParser parser = Jwts.parserBuilder()
                .setSigningKey(cachedKey)
                .build();
        return parser.parseClaimsJws(token).getBody();
    }

    private boolean isTokenExpired(String token) {
        ensureJwtEnabled();
        return extractExpiration(token).before(new Date());
    }

    private void ensureJwtEnabled() {
        if (!jwtConfig.isEnabled()) {
            throw new IllegalStateException("JWT is disabled via 'auth.jwt.enabled=false'.");
        }
    }
}
