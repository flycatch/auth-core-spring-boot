package com.flycatch.authcore.controllers;

import com.flycatch.authcore.dto.response.MessageResponse;
import com.flycatch.authcore.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * White-label Logout — enable via: auth.endpoints.logout-enabled: true
 * Session mode: invalidates HTTP session and clears JSESSIONID.
 * JWT mode: clears refresh cookie if configured.
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@ConditionalOnProperty(prefix = "auth.endpoints", name = "logout-enabled", havingValue = "true", matchIfMissing = false)
public class LogoutController {

    private final AuthService authService;

    @PostMapping("/logout")
    public ResponseEntity<MessageResponse> logout(HttpServletRequest request, HttpServletResponse response) {
        authService.logout(request, response);
        return ResponseEntity.ok(new MessageResponse("LOGOUT_SUCCESS"));
    }
}
