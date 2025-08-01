package com.flycatch.authcore.util;

import com.flycatch.authcore.config.AuthCoreConfig;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.*;
import java.util.function.Function;

@Component
public class JwtUtil {

    private final AuthCoreConfig.Jwt jwtConfig;

    public JwtUtil(AuthCoreConfig authCoreConfig) {
        this.jwtConfig = authCoreConfig.getJwt();
    }

    public String generateAccessToken(String username, Map<String, Object> claims) {
        return generateToken(username, jwtConfig.getAccessTokenExpiration(), claims);
    }

    public String generateRefreshToken(String username) {
        return generateToken(username, jwtConfig.getRefreshTokenExpiration(), new HashMap<>());
    }

    private String generateToken(String username, long expirationTime, Map<String, Object> claims) {
        byte[] keyBytes = Base64.getDecoder().decode(jwtConfig.getSecret());
        Key key = new SecretKeySpec(keyBytes, SignatureAlgorithm.HS256.getJcaName());

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean validateToken(String token, String username) {
        final String extractedUsername = extractUsername(token);
        return extractedUsername.equals(username) && !isTokenExpired(token);
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Map<String, Object> extractAllClaimsAsMap(String token) {
        return new HashMap<>(extractAllClaims(token));
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // made public so other classes like JwtAuthFilter can use it
    public Claims extractAllClaims(String token) {
        byte[] keyBytes = Base64.getDecoder().decode(jwtConfig.getSecret());
        SecretKey key = Keys.hmacShaKeyFor(keyBytes);

        JwtParser parser = Jwts.parserBuilder()
                .setSigningKey(key)
                .build();

        return parser.parseClaimsJws(token).getBody();
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }
}
