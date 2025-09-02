package com.flycatch.authcore.security;

import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;

public class SimplePermissionEvaluator implements PermissionEvaluator {
    @Override
    public boolean hasPermission(Authentication auth, Object targetDomainObject, Object permission) {
        return check(auth, permission);
    }
    @Override
    public boolean hasPermission(Authentication auth, Serializable targetId, String targetType, Object permission) {
        return check(auth, permission);
    }
    private boolean check(Authentication auth, Object permission) {
        if (auth == null || permission == null) return false;
        String p = String.valueOf(permission).trim();
        String pPref = p.startsWith("PERM_") ? p : "PERM_" + p;
        for (GrantedAuthority ga : auth.getAuthorities()) {
            String a = ga.getAuthority();
            if (p.equals(a) || pPref.equals(a)) return true;
        }
        return false;
    }
}
