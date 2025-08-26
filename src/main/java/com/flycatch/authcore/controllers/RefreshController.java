package com.flycatch.authcore.controllers;

import com.flycatch.authcore.config.AuthCoreConfig;
import com.flycatch.authcore.dto.request.RefreshRequest;
import com.flycatch.authcore.dto.response.AuthResponse;
import com.flycatch.authcore.dto.response.MessageResponse;
import com.flycatch.authcore.service.AuthService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.Map;

/**
 * White-label Refresh — enable via: auth.endpoints.refresh-enabled: true
 * Accepts refresh token in body or cookie (if cookies.enabled = true).
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@ConditionalOnProperty(prefix = "auth.endpoints", name = "refresh-enabled", havingValue = "true", matchIfMissing = false)
public class RefreshController {

    private final AuthService authService;
    private final AuthCoreConfig cfg;

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody(required = false) RefreshRequest body,
                                     HttpServletRequest request,
                                     HttpServletResponse response) {

        String token = (body != null) ? body.getRefreshToken() : null;

        // Try cookie when body missing and cookies are enabled
        if ((token == null || token.isBlank()) && cfg.getCookies().isEnabled()) {
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                String name = cfg.getCookies().getName();
                token = Arrays.stream(cookies)
                        .filter(c -> name.equals(c.getName()))
                        .map(Cookie::getValue)
                        .findFirst()
                        .orElse(null);
            }
        }

        if (token == null || token.isBlank()) {
            return ResponseEntity.badRequest().body(new MessageResponse("REFRESH_TOKEN_REQUIRED"));
        }

        Map<String, String> out = authService.refreshAccessToken(token, response);

        return ResponseEntity.ok(new AuthResponse(
                out.get("accessToken"),
                out.get("refreshToken"),
                "REFRESHED"
        ));
    }
}
