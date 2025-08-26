package com.flycatch.authcore.controllers;

import com.flycatch.authcore.dto.request.LoginRequest;
import com.flycatch.authcore.dto.response.AuthResponse;
import com.flycatch.authcore.dto.response.MessageResponse;
import com.flycatch.authcore.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
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

        return ResponseEntity.ok(new AuthResponse(
                result.get("accessToken"),
                result.get("refreshToken"),
                result.getOrDefault("message", "OK")
        ));
    }

    private static String firstNonBlank(String... vals) {
        if (vals == null) return null;
        for (String v : vals) if (!isBlank(v)) return v;
        return null;
    }

    private static boolean isBlank(String s) { return s == null || s.isBlank(); }
}
