package com.flycatch.authcore.spi;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Map;

public interface JwtClaimsProvider {
    String extractUsername(Object user);
    String extractPassword(Object user);
    Map<String, Object> extractClaims(Object user);
    Collection<? extends GrantedAuthority> extractAuthorities(Map<String, Object> claims);
}
