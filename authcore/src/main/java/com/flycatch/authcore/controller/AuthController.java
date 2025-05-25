package com.flycatch.authcore.controller;

import com.flycatch.authcore.config.AuthCoreConfig;
import com.flycatch.authcore.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;
    private final AuthCoreConfig authCoreConfig;

    public AuthController(AuthService authService, AuthCoreConfig authCoreConfig) {
        this.authService = authService;
        this.authCoreConfig = authCoreConfig;
    }

    @PostMapping
    public ResponseEntity<?> handleAuth(@RequestBody Map<String, String> request, HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        String action = request.get("action");

        switch (action) {
            case "login":
                return ResponseEntity.ok(authService.authenticate(
                        request.get("username") != null ? request.get("username") : request.get("email"),
                        request.get("password"),
                        httpResponse
                ));
            case "register":
                return ResponseEntity.ok(authService.register(
                        request.get("username"),
                        request.get("email"),
                        request.get("password")
                ));

            case "refresh":
                // Check if refresh tokens are enabled
                if (!authCoreConfig.isEnableRefreshToken()) {
                    return ResponseEntity.badRequest().body(Map.of("error", "Refresh token is disabled"));
                }

                // Extract refresh token from cookies
                String refreshToken = getCookieValue(httpRequest, authCoreConfig.getCookieName());
                if (refreshToken == null) {
                    return ResponseEntity.badRequest().body(Map.of("error", "Missing refresh token in cookies"));
                }
                return ResponseEntity.ok(authService.refreshAccessToken(refreshToken, httpResponse));

            case "logout":
                return ResponseEntity.ok(authService.logout(httpResponse));

            default:
                return ResponseEntity.badRequest().body(Map.of("error", "Invalid action"));
        }
    }

    /**
     * Helper method to retrieve cookie value by name.
     */
    private String getCookieValue(HttpServletRequest request, String cookieName) {
        if (request.getCookies() != null) {
            for (jakarta.servlet.http.Cookie cookie : request.getCookies()) {
                if (cookie.getName().equals(cookieName)) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
