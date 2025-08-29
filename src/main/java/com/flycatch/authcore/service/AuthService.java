package com.flycatch.authcore.service;

import com.flycatch.authcore.config.AuthCoreConfig;
import com.flycatch.authcore.spi.JwtClaimsProvider;
import com.flycatch.authcore.util.JwtUtil;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class AuthService  {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final UserDetailsService userService;
    private final JwtUtil jwtUtil;
    private final AuthCoreConfig cfg;
    private final JwtClaimsProvider claimsProvider;
    private final AuthenticationManager authenticationManager;

    public AuthService(UserDetailsService userService,
                       PasswordEncoder passwordEncoder,
                       JwtUtil jwtUtil,
                       AuthCoreConfig cfg,
                       JwtClaimsProvider claimsProvider,
                       AuthenticationManager authenticationManager) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
        this.cfg = cfg;
        this.claimsProvider = claimsProvider;
        this.authenticationManager = authenticationManager;
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

    public Map<String, String> authenticate(String loginId,
                                            String password,
                                            HttpServletResponse response,
                                            HttpServletRequest request) {
        if (cfg.getLogging().isEnabled()) {
            logger.info("Authenticating user: {}", loginId);
        }

        try{
        Authentication authentication = authenticationManager.authenticate
                (new UsernamePasswordAuthenticationToken(loginId,password));
            UserDetails user = (UserDetails) authentication.getPrincipal();
            List<String> roles = user.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();


        // ===== SESSION MODE =====
        if (cfg.getSession().isEnabled()) {
            // Build an Authentication with the user's authorities
            // Put it into the SecurityContext and persist it to the HTTP session
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);

            // Save context so subsequent requests with JSESSIONID are authenticated
            new HttpSessionSecurityContextRepository().saveContext(context, request, response);

            Map<String, String> out = new HashMap<>();
            out.put("message", "SESSION_AUTHENTICATED");
            out.put("roles", String.join(",", roles));
            return out;
        }

        // ===== JWT MODE =====
        if (cfg.getJwt().isEnabled()) {
            String accessToken = jwtUtil.generateAccessToken(
                    user.getUsername(),
                    claimsProvider != null ? claimsProvider.extractClaims(user) : null
            );

            Map<String, String> out = new HashMap<>();
            out.put("accessToken", accessToken);
            out.put("message", "JWT_AUTHENTICATED");
            out.put("roles", String.join(",", roles));

            if (isRefreshEnabled()) {
                String refreshToken = jwtUtil.generateRefreshToken(user.getUsername());
                out.put("refreshToken", refreshToken);

                if (cfg.getCookies().isEnabled()) {
                    setCookie(response, cfg.getCookies().getName(), refreshToken, cfg.getCookies().getMaxAge());
                }
            }

            return out;
        }

        throw new IllegalStateException("No authentication mechanism enabled.");
        } catch (Exception ex) {
            logger.error("Authentication failed for user {}", loginId, ex);
            return invalid();
        }
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

        String newAccessToken = jwtUtil.generateAccessToken(
                username,
                claimsProvider != null ? claimsProvider.extractClaims(user) : null
        );

        Map<String, String> out = new HashMap<>();
        out.put("accessToken", newAccessToken);

        if (isRefreshEnabled()) {
            String newRefreshToken = jwtUtil.generateRefreshToken(username);
            out.put("refreshToken", newRefreshToken);

            if (cfg.getCookies().isEnabled()) {
                setCookie(response, cfg.getCookies().getName(), newRefreshToken, cfg.getCookies().getMaxAge());
            }
        }

        return out;
    }

    /**
     * Logout for both modes:
     * - SESSION mode: invalidates HttpSession, clears SecurityContext, expires JSESSIONID.
     * - JWT mode: clears refresh cookie if enabled. (Access tokens remain statelessly valid until expiry.)
     */
    public Map<String, String> logout(HttpServletRequest request, HttpServletResponse response) {
        // Invalidate Spring session if present (also removes JDBC row when using spring-session-jdbc)
        var session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }

        // Clear SecurityContext for this thread
        SecurityContextHolder.clearContext();

        // Always expire JSESSIONID so client stops sending old session id
        ResponseCookie jsid = ResponseCookie.from("JSESSIONID", "")
                .path("/")
                .httpOnly(true)
                .maxAge(Duration.ZERO)
                .build();
        response.addHeader("Set-Cookie", jsid.toString());

        // If refresh cookies are used (JWT flow), clear that too
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
