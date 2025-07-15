package com.flycatch.authcore.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.function.Function;

@Component
public class JwtUtil {

    @Value("${auth.jwt.secret}")
    private String secretKey;

    @Value("${auth.jwt.access-token-expiration}")
    private long accessTokenExpiration;

    @Value("${auth.jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    public String generateAccessToken(String username, Set<String> roles) {
        return generateToken(username, accessTokenExpiration, roles);
    }

    public String generateRefreshToken(String username) {
        return generateToken(username, refreshTokenExpiration, null);
    }

    private String generateToken(String username, long expirationTime, Set<String> roles) {
        Map<String, Object> claims = new HashMap<>();
        if (roles != null) {
            claims.put("roles", roles);
        }

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    public boolean validateToken(String token, String username) {
        final String extractedUsername = extractUsername(token);
        return extractedUsername.equals(username) && !isTokenExpired(token);
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Set<String> extractRoles(String token) {
        final Claims claims = extractAllClaims(token);
        Object roles = claims.get("roles");
        if (roles instanceof List<?>) {
            Set<String> roleSet = new HashSet<>();
            for (Object role : (List<?>) roles) {
                roleSet.add(String.valueOf(role));
            }
            return roleSet;
        }
        return Set.of();
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(token)
                .getBody();
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }
}
