package com.flycatch.authcore.spi;

import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;

public interface RbacProvider {
    List<String> getUserRoles(UserDetails user);
    default Boolean hasRole(UserDetails user, String role) {
        return getUserRoles(user).contains(role);
    }
}
