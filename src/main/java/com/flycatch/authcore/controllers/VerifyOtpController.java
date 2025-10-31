package com.flycatch.authcore.controllers;

import com.flycatch.authcore.config.AuthCoreConfig;
import com.flycatch.authcore.dto.response.AuthResponse;
import com.flycatch.authcore.dto.response.MessageResponse;
import com.flycatch.authcore.service.AuthService;
import com.flycatch.authcore.util.OtpUtil;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@ConditionalOnProperty(prefix="auth.two-factor", name="enabled", havingValue="true", matchIfMissing=false)
public class VerifyOtpController {

    private final AuthCoreConfig cfg;
    private final AuthService authService;
    private final OtpUtil otpUtil;

    // ✅ Use JSON instead of request params
    public static class OtpRequest {
        public String username;
        public String otp;
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<?> verifyOtp(@RequestBody OtpRequest req, HttpServletResponse res) {
        if (req.username == null || req.otp == null) {
            return ResponseEntity.badRequest().body(new MessageResponse("USERNAME_AND_OTP_REQUIRED"));
        }

        if (!otpUtil.verify(req.username, req.otp)) {
            return ResponseEntity.badRequest().body(new MessageResponse("INVALID_OR_EXPIRED_OTP"));
        }

        // OTP verified — issue tokens same as normal login
        Map<String, String> tokens = authService.authenticate(req.username, "__OTP_VERIFIED__", res, null);
        if (tokens.containsKey("accessToken")) {
            return ResponseEntity.ok(new AuthResponse(
                    tokens.get("accessToken"),
                    tokens.get("refreshToken"),
                    tokens.getOrDefault("message", "OK")
            ));
        }

        return ResponseEntity.badRequest().body(new MessageResponse("LOGIN_FAILED"));
    }
}
