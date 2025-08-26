package com.flycatch.authcore.spi;

import org.springframework.security.core.userdetails.UserDetails;

import java.util.Map;

public interface JwtClaimsProvider  {

    Map<String, Object> extractClaims(UserDetails user);

}
