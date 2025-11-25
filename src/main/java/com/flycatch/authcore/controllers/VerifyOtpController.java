package com.flycatch.authcore.controllers;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.flycatch.authcore.config.AuthCoreConfig;
import com.flycatch.authcore.dto.response.AuthResponse;
import com.flycatch.authcore.dto.response.MessageResponse;
import com.flycatch.authcore.service.AuthService;
import com.flycatch.authcore.util.OtpUtil;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * White-label OTP verification endpoint.
 * Enabled when: auth.two-factor.enabled = true
 *
 * Accepts loginId/username/email in the request and resolves the canonical username
 * before calling OtpUtil.verify().
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@ConditionalOnProperty(prefix = "auth.two-factor", name = "enabled", havingValue = "true", matchIfMissing = false)
public class VerifyOtpController {

    private static final Logger log = LoggerFactory.getLogger(VerifyOtpController.class);

    private final AuthCoreConfig cfg;
    private final AuthService authService;
    private final OtpUtil otpUtil;
    private final UserDetailsService userDetailsService;

    /**
     * Request body for OTP verification.
     *
     * loginId can be:
     *  - username
     *  - email
     *  - any identifier your UserDetailsService understands
     */
    public static class OtpRequest {

        @JsonAlias({"username", "email"}) // <--- add this
        public String loginId;

        public String otp;
    }


    @PostMapping("/verify-otp")
    public ResponseEntity<?> verifyOtp(@RequestBody OtpRequest req, HttpServletResponse res) {
        // Basic null checks
        if (req == null || req.loginId == null || req.otp == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("UNAUTHORIZED"));
        }

        try {
            // 1) Resolve canonical username via your UserDetailsService
            UserDetails user = userDetailsService.loadUserByUsername(req.loginId);
            String canonicalUsername = user.getUsername(); // this is the same key used in AuthService/OtpUtil

            // 2) Verify OTP against that canonical username
            boolean ok = otpUtil.verify(canonicalUsername, req.otp);
            if (!ok) {
                if (cfg.getLogging().isEnabled()) {
                    log.info("OTP verification failed for loginId={} (canonical username={})", req.loginId, canonicalUsername);
                }
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new MessageResponse("UNAUTHORIZED"));
            }

            // 3) OTP verified — issue tokens same as normal login, using OTP bypass
            Map<String, String> tokens = authService.authenticate(
                    req.loginId,          // still pass the same loginId (email/username)
                    "__OTP_VERIFIED__",   // magic bypass password
                    res,
                    null                  // no HttpServletRequest (JWT mode)
            );

            String accessToken = tokens.get("accessToken");
            if (accessToken != null && !accessToken.isBlank()) {
                return ResponseEntity.ok(new AuthResponse(
                        accessToken,
                        tokens.get("refreshToken"),
                        tokens.getOrDefault("message", "OK")
                ));
            }

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("UNAUTHORIZED"));

        } catch (Exception ex) {
            if (cfg.getLogging().isEnabled()) {
                log.warn("OTP verify failed for loginId={}: {}", req.loginId, ex.getMessage(), ex);
            }
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("UNAUTHORIZED"));
        }
    }
}
