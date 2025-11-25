package com.flycatch.authcore.oauth2;

import com.flycatch.authcore.config.AuthCoreConfig;
import com.flycatch.authcore.dto.response.AuthResponse;
import com.flycatch.authcore.dto.response.MessageResponse;
import com.flycatch.authcore.service.AuthService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth/oauth2")
@RequiredArgsConstructor
public class OAuth2CodeExchangeController {

    private static final Logger log = LoggerFactory.getLogger(OAuth2CodeExchangeController.class);

    private final OAuth2AuthorizationCodeService codeService;
    private final AuthService authService;
    private final AuthCoreConfig cfg;

    @Getter
    @Setter
    public static class CodeExchangeRequest {
        @NotBlank
        private String code;
    }

    /**
     * Server-to-server endpoint:
     *  Client backend calls this with the short-lived code.
     *  Returns accessToken + refreshToken on success.
     *
     *  On any failure, response is always:
     *    - HTTP 401
     *    - body: {"message": "UNAUTHORIZED"}
     *  Detailed reason is logged only when auth.logging.enabled = true.
     */
    @PostMapping("/exchange")
    public ResponseEntity<?> exchange(@RequestBody CodeExchangeRequest req,
                                      HttpServletResponse res) {

        // Code-flow disabled → treat as unauthorized for clients, log internal reason.
        if (!cfg.getOauth2().isAuthorizationCodeEnabled()) {
            if (cfg.getLogging().isEnabled()) {
                log.warn("OAuth2 code exchange attempted but authorization-code flow is disabled.");
            }
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("UNAUTHORIZED"));
        }

        // Missing body or code → log details, return generic UNAUTHORIZED.
        if (req == null || req.getCode() == null || req.getCode().isBlank()) {
            if (cfg.getLogging().isEnabled()) {
                log.warn("OAuth2 code exchange failed: missing or blank code in request.");
            }
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("UNAUTHORIZED"));
        }

        // Consume code (one-time). If null or expired → unauthorized to client.
        String username = codeService.consumeCode(req.getCode());
        if (username == null) {
            if (cfg.getLogging().isEnabled()) {
                log.warn("OAuth2 code exchange failed: invalid or expired code.");
            }
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("UNAUTHORIZED"));
        }

        try {
            Map<String, String> tokens = authService.issueTokensForOAuth2(username, res);
            String accessToken = tokens.get("accessToken");

            if (accessToken == null || accessToken.isBlank()) {
                if (cfg.getLogging().isEnabled()) {
                    log.warn("OAuth2 code exchange failed: token issuance returned empty access token for user '{}'.", username);
                }
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new MessageResponse("UNAUTHORIZED"));
            }

            return ResponseEntity.ok(new AuthResponse(
                    accessToken,
                    tokens.get("refreshToken"),
                    tokens.getOrDefault("message", "OK")
            ));
        } catch (Exception ex) {
            if (cfg.getLogging().isEnabled()) {
                log.error("OAuth2 code exchange failed for user '{}': {}", username, ex.getMessage(), ex);
            }
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new MessageResponse("UNAUTHORIZED"));
        }
    }
}
