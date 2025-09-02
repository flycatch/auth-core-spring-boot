package com.flycatch.authcore.security;

public final class AuthConstants {
    private AuthConstants() {}

    public static final String CLAIM_AUTHORITIES = "authorities"; // List<String>
    public static final String CLAIM_ROLES = "roles";             // List<String>, optional mirror
}
