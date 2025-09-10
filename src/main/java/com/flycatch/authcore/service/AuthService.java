package com.flycatch.authcore.service;

import com.flycatch.authcore.config.AuthCoreConfig;
import com.flycatch.authcore.rbac.RbacAuthorityService;
import com.flycatch.authcore.security.AuthConstants;
import com.flycatch.authcore.spi.JwtClaimsProvider;
import com.flycatch.authcore.util.JwtUtil;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.http.ResponseCookie;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final UserDetailsService userService;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthCoreConfig cfg;
    private final JwtClaimsProvider claimsProvider;
    private final RbacAuthorityService rbac;

    public AuthService(UserDetailsService userService,
                       PasswordEncoder passwordEncoder,
                       JwtUtil jwtUtil,
                       AuthCoreConfig cfg,
                       JwtClaimsProvider claimsProvider,
                       RbacAuthorityService rbac) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.cfg = cfg;
        this.claimsProvider = claimsProvider;
        this.rbac = rbac;
    }

    @PostConstruct
    public void validateAuthMode() {
        if (!cfg.getJwt().isEnabled() && !cfg.getSession().isEnabled()) {
            throw new IllegalStateException("Both JWT and Session authentication are disabled. Please enable at least one in config.");
        }
    }

    private boolean isRefreshEnabled() {
        return cfg.getJwt().isRefreshTokenEnabled();
    }

    // ========== Username/Password login ==========
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

        if (!passwordEncoder.matches(password, user.getPassword())) {
            return invalid();
        }

        return issueAuthentication(user, request, response, "PASSWORD_AUTHENTICATED");
    }

    // ========== OAuth2 login ==========
    public Map<String, String> authenticateOAuth2(String username,
                                                  HttpServletRequest request,
                                                  HttpServletResponse response) {
        final UserDetails user = userService.loadUserByUsername(username);
        return issueAuthentication(user, request, response, "OAUTH2_AUTHENTICATED");
    }

    // ========== Shared method for issuing Session/JWT ==========
    private Map<String, String> issueAuthentication(UserDetails user,
                                                    HttpServletRequest request,
                                                    HttpServletResponse response,
                                                    String successMessage) {
        // ===== SESSION MODE =====
        if (cfg.getSession().isEnabled()) {
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());

            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);

            // Persist security context so subsequent requests with JSESSIONID are authenticated
            new HttpSessionSecurityContextRepository().saveContext(context, request, response);

            Map<String, String> out = new HashMap<>();
            out.put("message", successMessage + "_SESSION");
            return out;
        }

        // ===== JWT MODE =====
        if (cfg.getJwt().isEnabled()) {
            return issueJwt(user, response, successMessage);
        }

        throw new IllegalStateException("No authentication mechanism enabled.");
    }

    private Map<String, String> issueJwt(UserDetails user,
                                         HttpServletResponse response,
                                         String successMessage) {
        // take authorities from UserDetails and expand ROLE_* -> YAML permissions
        Set<String> baseAuthorities = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
        Set<String> expandedAuthorities = rbac.expandAuthorities(baseAuthorities);

        Map<String, Object> claims = new HashMap<>();
        if (claimsProvider != null) {
            Map<String, Object> extra = claimsProvider.extractClaims(user);
            if (extra != null) claims.putAll(extra);
        }

        // embed final authorities + roles into token (for downstream method security)
        List<String> authorities = expandedAuthorities.stream().sorted().toList();
        claims.put(AuthConstants.CLAIM_AUTHORITIES, authorities);
        List<String> roles = authorities.stream().filter(a -> a.startsWith("ROLE_")).toList();
        claims.put(AuthConstants.CLAIM_ROLES, roles);

        String accessToken = jwtUtil.generateAccessToken(user.getUsername(), claims);

        Map<String, String> out = new HashMap<>();
        out.put("accessToken", accessToken);
        out.put("message", successMessage + "_JWT");

        if (isRefreshEnabled()) {
            String refreshToken = jwtUtil.generateRefreshToken(user.getUsername());
            out.put("refreshToken", refreshToken);

            if (cfg.getCookies().isEnabled()) {
                setCookie(response, cfg.getCookies().getName(), refreshToken, cfg.getCookies().getMaxAge());
            }
        }

        return out;
    }

    // ========== Refresh ==========
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
        return issueJwt(user, response, "JWT_REFRESHED");
    }

    // ========== Logout ==========
    public Map<String, String> logout(HttpServletRequest request, HttpServletResponse response) {
        var session = request.getSession(false);
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
        if (cfg.getLogging().isEnabled()) logger.info("User logged out (session invalidated, cookies cleared).");
        return out;
    }

    private Map<String, String> invalid() {
        Map<String, String> out = new HashMap<>();
        out.put("message", "INVALID_CREDENTIALS");
        return out;
    }

    /** Use ResponseCookie so SameSite is honored */
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
}
