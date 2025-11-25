package com.flycatch.authcore.service;

import com.flycatch.authcore.config.AuthCoreConfig;
import com.flycatch.authcore.rbac.RbacAuthorityService;
import com.flycatch.authcore.security.AuthConstants;
import com.flycatch.authcore.spi.JwtClaimsProvider;
import com.flycatch.authcore.spi.OtpSender;
import com.flycatch.authcore.util.JwtUtil;
import com.flycatch.authcore.util.OtpUtil;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final UserDetailsService userService;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthCoreConfig cfg;
    private final Optional<JwtClaimsProvider> claimsProvider;
    private final RbacAuthorityService rbac;
    private final OtpUtil otpUtil;
    private final OtpSender otpSender;

    public AuthService(UserDetailsService userService,
                       PasswordEncoder passwordEncoder,
                       JwtUtil jwtUtil,
                       AuthCoreConfig cfg,
                       Optional<JwtClaimsProvider> claimsProvider,
                       RbacAuthorityService rbac,
                       OtpUtil otpUtil,
                       OtpSender otpSender) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.cfg = cfg;
        this.claimsProvider = claimsProvider;
        this.rbac = rbac;
        this.otpUtil = otpUtil;
        this.otpSender = otpSender;
    }

    @PostConstruct
    public void validateAuthMode() {
        if (!cfg.getJwt().isEnabled() && !cfg.getSession().isEnabled()) {
            throw new IllegalStateException(
                    "Both JWT and Session authentication are disabled. Please enable at least one in config."
            );
        }
    }

    private boolean isRefreshEnabled() {
        return cfg.getJwt().isRefreshTokenEnabled();
    }

    public Map<String, String> authenticate(String loginId,
                                            String password,
                                            HttpServletResponse response,
                                            HttpServletRequest request) {

        if (cfg.getLogging().isEnabled()) {
            logger.info("Authenticating user: {}", loginId);
        }

        final UserDetails user;
        try {
            user = userService.loadUserByUsername(loginId);
        } catch (UsernameNotFoundException ex) {
            return invalid();
        }

        // PASSWORD CHECK / OTP BYPASS
        final boolean otpBypass = "__OTP_VERIFIED__".equals(password);
        if (!otpBypass && !passwordEncoder.matches(password, user.getPassword())) {
            return invalid();
        }

        // TWO-FACTOR AUTH (EMAIL OTP) BEFORE ISSUING ANY TOKENS
        if (cfg.getTwoFactor().isEnabled() && !otpBypass) {
            String destination = (user.getUsername() != null && user.getUsername().contains("@"))
                    ? user.getUsername()
                    : (user.getUsername() + "@example.local");

            String otp = otpUtil.generate(user.getUsername());
            otpSender.sendOtp(user.getUsername(), destination, otp);

            Map<String, String> out = new HashMap<>();
            out.put("message", "OTP_REQUIRED");
            return out;
        }

        // SESSION MODE (if enabled AND request is non-null)
        if (cfg.getSession().isEnabled() && request != null) {
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());

            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);

            new HttpSessionSecurityContextRepository().saveContext(context, request, response);

            Map<String, String> out = new HashMap<>();
            out.put("message", "SESSION_AUTHENTICATED");
            return out;
        }

        // JWT MODE
        if (cfg.getJwt().isEnabled()) {
            return issueJwtTokens(user, response, "JWT_AUTHENTICATED");
        }

        throw new IllegalStateException("No authentication mechanism enabled.");
    }

    public Map<String, String> refreshAccessToken(String refreshToken, HttpServletResponse response) {
        if (!isRefreshEnabled()) {
            throw new UnsupportedOperationException("Refresh token is disabled.");
        }
        if (!cfg.getJwt().isEnabled()) {
            throw new IllegalStateException("JWT is disabled. Cannot refresh token.");
        }

        String username = jwtUtil.extractUsername(refreshToken);
        if (!jwtUtil.validateToken(refreshToken, username)) {
            throw new IllegalArgumentException("Invalid refresh token");
        }

        final UserDetails user = userService.loadUserByUsername(username);
        return issueJwtTokens(user, response, "REFRESHED");
    }

    /**
     * OAuth2 code-flow helper:
     *  Given a username (resolved during OAuth2 success), issue access/refresh tokens.
     */
    public Map<String, String> issueTokensForOAuth2(String username, HttpServletResponse response) {
        if (!cfg.getJwt().isEnabled()) {
            throw new IllegalStateException("JWT is disabled. OAuth2 code flow requires JWT mode.");
        }
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("username is required for OAuth2 token issuance");
        }

        final UserDetails user = userService.loadUserByUsername(username);
        return issueJwtTokens(user, response, "OAUTH2_JWT_ISSUED");
    }

    /**
     * Logout for both modes:
     * - SESSION mode: invalidates HttpSession, clears SecurityContext, expires JSESSIONID.
     * - JWT mode: clears refresh cookie if enabled.
     */
    public Map<String, String> logout(HttpServletRequest request, HttpServletResponse response) {
        var session = request != null ? request.getSession(false) : null;
        if (session != null) {
            session.invalidate();
        }

        SecurityContextHolder.clearContext();

        ResponseCookie jsid = ResponseCookie.from("JSESSIONID", "")
                .path("/")
                .httpOnly(true)
                .maxAge(Duration.ZERO)
                .build();
        response.addHeader("Set-Cookie", jsid.toString());

        if (cfg.getCookies().isEnabled()) {
            ResponseCookie rt = ResponseCookie.from(cfg.getCookies().getName(), "")
                    .path("/")
                    .httpOnly(cfg.getCookies().isHttpOnly())
                    .secure(cfg.getCookies().isSecure())
                    .sameSite(cfg.getCookies().getSameSite())
                    .maxAge(Duration.ZERO)
                    .build();
            response.addHeader("Set-Cookie", rt.toString());
        }

        Map<String, String> out = new HashMap<>();
        out.put("message", "LOGOUT_SUCCESS");
        if (cfg.getLogging().isEnabled()) {
            logger.info("User logged out (session invalidated, cookies cleared).");
        }
        return out;
    }

    private Map<String, String> invalid() {
        Map<String, String> out = new HashMap<>();
        out.put("message", "UNAUTHORIZED");
        return out;
    }

    /**
     * Core JWT issuance logic reused by:
     *  - username/password login
     *  - refreshAccessToken
     *  - OAuth2 code-flow exchange
     */
    private Map<String, String> issueJwtTokens(UserDetails user,
                                               HttpServletResponse response,
                                               String messageForClient) {

        if (!cfg.getJwt().isEnabled()) {
            throw new IllegalStateException("JWT is disabled via configuration.");
        }

        Set<String> baseAuthorities = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
        Set<String> expandedAuthorities = rbac.expandAuthorities(baseAuthorities);

        Map<String, Object> claims = new HashMap<>();
        claimsProvider.ifPresent(provider -> {
            try {
                Map<String, Object> extra = provider.extractClaims(user);
                if (extra != null) {
                    claims.putAll(extra);
                }
            } catch (Exception e) {
                if (cfg.getLogging().isEnabled()) {
                    logger.warn("JwtClaimsProvider threw exception: {}", e.getMessage(), e);
                }
            }
        });

        List<String> authorities = expandedAuthorities.stream().sorted().toList();
        claims.put(AuthConstants.CLAIM_AUTHORITIES, authorities);
        List<String> roles = authorities.stream().filter(a -> a.startsWith("ROLE_")).toList();
        claims.put(AuthConstants.CLAIM_ROLES, roles);

        String accessToken = jwtUtil.generateAccessToken(user.getUsername(), claims);

        Map<String, String> out = new HashMap<>();
        out.put("accessToken", accessToken);
        out.put("message", messageForClient);

        if (isRefreshEnabled()) {
            String refreshToken = jwtUtil.generateRefreshToken(user.getUsername());
            out.put("refreshToken", refreshToken);

            if (cfg.getCookies().isEnabled()) {
                setCookie(response, cfg.getCookies().getName(), refreshToken, cfg.getCookies().getMaxAge());
            }
        }

        return out;
    }

    private void setCookie(HttpServletResponse response, String name, String value, int maxAgeSeconds) {
        ResponseCookie cookie = ResponseCookie.from(name, value)
                .httpOnly(cfg.getCookies().isHttpOnly())
                .secure(cfg.getCookies().isSecure())
                .sameSite(cfg.getCookies().getSameSite())
                .path("/")
                .maxAge(Duration.ofSeconds(maxAgeSeconds))
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
    }

    @SuppressWarnings("unused")
    private void clearCookie(HttpServletResponse response, String name) {
        ResponseCookie cookie = ResponseCookie.from(name, "")
                .httpOnly(cfg.getCookies().isHttpOnly())
                .secure(cfg.getCookies().isSecure())
                .sameSite(cfg.getCookies().getSameSite())
                .path("/")
                .maxAge(Duration.ZERO)
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
    }
}
