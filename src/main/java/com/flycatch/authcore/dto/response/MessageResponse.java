package com.flycatch.authcore.dto.response;

import lombok.Getter;

/** Minimal message response for simple outcomes (e.g., logout) or errors. */
@Getter
public class MessageResponse {
    private final String message;

    public MessageResponse(String message) {
        this.message = message;
    }
}
