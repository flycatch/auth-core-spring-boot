package com.flycatch.authcore.dto.response;

import lombok.Getter;

/**
 * Standard auth response containing tokens and a message.
 * - For login/refresh (JWT mode), accessToken is returned (and refreshToken if enabled)
 * - For session mode login, only message may be present.
 */
@Getter
public class AuthResponse {
    private final String accessToken;
    private final String refreshToken;
    private final String message;

    public AuthResponse(String accessToken, String refreshToken, String message) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.message = message;
    }
}
