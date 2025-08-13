package com.flycatch.authcore.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

/**
 * Global refresh request DTO.
 * If cookie-based refresh is enabled and body is absent, controller will read cookie.
 */
@Getter
@Setter
public class RefreshRequest {
    @NotBlank
    private String refreshToken;
}
