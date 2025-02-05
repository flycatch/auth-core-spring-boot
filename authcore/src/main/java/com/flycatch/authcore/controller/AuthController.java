package com.flycatch.authcore.controller;

import com.flycatch.authcore.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping
    public ResponseEntity<?> handleAuth(@RequestBody Map<String, String> request) {
        String action = request.get("action");

        switch (action) {
            case "login":
                return ResponseEntity.ok(authService.authenticate(request.get("username"), request.get("password")));

            case "register":
                return ResponseEntity.ok(authService.register(request.get("username"), request.get("password")));

            case "refresh":
                return ResponseEntity.ok(Map.of("accessToken", authService.refreshAccessToken(request.get("refreshToken"))));

            default:
                return ResponseEntity.badRequest().body(Map.of("error", "Invalid action"));
        }
    }
}
