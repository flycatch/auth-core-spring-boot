package com.flycatch.authcore.dto.request;

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

/**
 * Global login request DTO.
 * Accepts any of: loginId, username, email
 */
@Getter
@Setter
public class LoginRequest {
    /** Primary field used by service (aliases map here) */
    @JsonAlias({"username", "email"})
    private String loginId;

    /** Optional raw aliases (mapped by @JsonAlias, still exposed for clarity) */
    private String username;
    private String email;

    @NotBlank
    private String password;
}
