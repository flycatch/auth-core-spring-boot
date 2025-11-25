package com.flycatch.authcore.controllers;

import com.flycatch.authcore.config.AuthCoreConfig;
import com.flycatch.authcore.dto.request.LoginRequest;
import com.flycatch.authcore.dto.response.AuthResponse;
import com.flycatch.authcore.dto.response.MessageResponse;
import com.flycatch.authcore.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * White-label Login — uses AuthService for consistency with refresh/logout.
 * Enable via: auth.endpoints.login-enabled: true
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@ConditionalOnProperty(prefix = "auth.endpoints", name = "login-enabled", havingValue = "true", matchIfMissing = false)
public class LoginController {

    private final AuthService authService;
    private final AuthCoreConfig cfg;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request,
                                   HttpServletRequest httpRequest,
                                   HttpServletResponse httpResponse) {

        String loginId = firstNonBlank(request.getLoginId(), request.getUsername(), request.getEmail());
        if (isBlank(loginId) || isBlank(request.getPassword())) {
            return ResponseEntity.badRequest().body(new MessageResponse("LOGIN_ID_AND_PASSWORD_REQUIRED"));
        }

        Map<String, String> result = authService.authenticate(
                loginId, request.getPassword(), httpResponse, httpRequest
        );

        String message = result.getOrDefault("message", "OK");

        // OTP step (not a security breach, just next step)
        if ("OTP_REQUIRED".equals(message)) {
            return ResponseEntity.ok(new MessageResponse("OTP_REQUIRED"));
        }

        // JWT mode
        if (cfg.getJwt().isEnabled()) {
            String accessToken = result.get("accessToken");
            if (accessToken == null || accessToken.isBlank()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new MessageResponse("UNAUTHORIZED"));
            }
            return ResponseEntity.ok(new AuthResponse(
                    accessToken,
                    result.get("refreshToken"),
                    message
            ));
        }

        // Session mode
        if (cfg.getSession().isEnabled()) {
            if (!"SESSION_AUTHENTICATED".equals(message)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new MessageResponse("UNAUTHORIZED"));
            }
            return ResponseEntity.ok(new MessageResponse(message));
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new MessageResponse("UNAUTHORIZED"));
    }

    private static String firstNonBlank(String... vals) {
        if (vals == null) return null;
        for (String v : vals) if (!isBlank(v)) return v;
        return null;
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}
