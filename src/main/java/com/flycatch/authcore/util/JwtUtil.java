package com.flycatch.authcore.util;

import com.flycatch.authcore.config.AuthCoreConfig;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtUtil {

    private static final Logger log = LoggerFactory.getLogger(JwtUtil.class);

    private final AuthCoreConfig cfg;
    private Key signingKey;

    public JwtUtil(AuthCoreConfig cfg) {
        this.cfg = cfg;
    }

    @PostConstruct
    public void init() {
        if (cfg.getJwt().isEnabled()) {
            String secret = cfg.getJwt().getSecret();
            if (secret == null || secret.isBlank()) {
                throw new IllegalStateException("JWT is enabled but 'auth.jwt.secret' is not configured.");
            }
            this.signingKey = buildKey(secret);
            if (cfg.getLogging().isEnabled()) {
                log.info("JwtUtil initialized (JWT enabled: true, refresh enabled: {})",
                        cfg.getJwt().isRefreshTokenEnabled());
            }
        } else if (cfg.getLogging().isEnabled()) {
            log.info("JwtUtil initialized (JWT enabled: false)");
        }
    }

    private Key buildKey(String secret) {
        try {
            byte[] decoded = Decoders.BASE64.decode(secret);
            return Keys.hmacShaKeyFor(decoded);
        } catch (IllegalArgumentException ex) {
            return Keys.hmacShaKeyFor(secret.getBytes());
        }
    }

    public String generateAccessToken(String username, Map<String, Object> extraClaims) {
        ensureEnabled();
        long now = System.currentTimeMillis();
        long expMillis = now + cfg.getJwt().getAccessTokenExpiration();
        Map<String, Object> claims = (extraClaims != null) ? new HashMap<>(extraClaims) : new HashMap<>();

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(expMillis))
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateRefreshToken(String username) {
        ensureEnabled();
        long now = System.currentTimeMillis();
        long expMillis = now + cfg.getJwt().getRefreshTokenExpiration();

        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(expMillis))
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();
    }

    public String extractUsername(String token) {
        return getAllClaims(token).getSubject();
    }

    public Map<String, Object> extractAllClaims(String token) {
        Claims claims = getAllClaims(token);
        return new HashMap<>(claims);
    }

    public boolean validateToken(String token, String expectedUsername) {
        try {
            Claims claims = getAllClaims(token);
            String subject = claims.getSubject();
            Date expiration = claims.getExpiration();
            return subject != null
                    && subject.equals(expectedUsername)
                    && expiration != null
                    && expiration.after(new Date());
        } catch (ExpiredJwtException e) {
            if (cfg.getLogging().isEnabled()) log.warn("JWT expired for subject: {}", e.getClaims().getSubject());
            return false;
        } catch (JwtException e) {
            if (cfg.getLogging().isEnabled()) log.warn("Invalid JWT: {}", e.getMessage());
            return false;
        }
    }

    private Claims getAllClaims(String token) {
        ensureEnabled();
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private void ensureEnabled() {
        if (!cfg.getJwt().isEnabled()) {
            throw new IllegalStateException("JWT is disabled via configuration.");
        }
        if (signingKey == null) {
            throw new IllegalStateException("JWT signing key not initialized.");
        }
    }
}
