package com.flycatch.authcore.service;

import com.flycatch.authcore.config.AuthCoreConfig;
import com.flycatch.authcore.spi.JwtClaimsProvider;
import com.flycatch.authcore.util.JwtUtil;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);
    private final UserDetailsService userService;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthCoreConfig authCoreConfig;
    private final JwtClaimsProvider claimsProvider;

    public AuthService(UserDetailsService userService, PasswordEncoder passwordEncoder, JwtUtil jwtUtil, AuthCoreConfig authCoreConfig, JwtClaimsProvider claimsProvider) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.authCoreConfig = authCoreConfig;
        this.claimsProvider = claimsProvider;
    }

    @PostConstruct
    public void validateAuthMode() {
        if (!authCoreConfig.getJwt().isEnabled() && !authCoreConfig.getSession().isEnabled()) {
            throw new IllegalStateException("Both JWT and Session authentication are disabled. Please enable at least one in config.");
        }
    }

    public Map<String, String> authenticate(String loginId, String password, HttpServletResponse response, HttpServletRequest request) {
        if (authCoreConfig.getLogging().isEnabled()) {
            logger.info("Authenticating user: {}", loginId);
        }

        Optional<UserDetails> userOpt = Optional.ofNullable(userService.loadUserByUsername(loginId));

        Map<String, String> responseData = new HashMap<>();

        if (userOpt.isPresent()) {
            UserDetails user = userOpt.get();
            String storedPassword = user.getPassword();
            String username =  user.getUsername();

            if (passwordEncoder.matches(password, storedPassword)) {

                // Session enabled
                if (authCoreConfig.getSession().isEnabled()) {
                    request.getSession(true).setAttribute("USER", user);
                    responseData.put("message", "SESSION_AUTHENTICATED");
                    return responseData;
                }

                //  JWT enabled
                if (authCoreConfig.getJwt().isEnabled()) {
                    String accessToken = jwtUtil.generateAccessToken(username, claimsProvider.extractClaims(user));
                    responseData.put("accessToken", accessToken);

                    if (authCoreConfig.getRefreshToken().isEnabled()) {
                        String refreshToken = jwtUtil.generateRefreshToken(username);
                        responseData.put("refreshToken", refreshToken);

                        if (authCoreConfig.getCookies().isEnabled()) {
                            setCookie(response, authCoreConfig.getCookies().getName(), refreshToken, authCoreConfig.getCookies().getMaxAge());
                        }
                    }

                    responseData.put("message", "JWT_AUTHENTICATED");
                    return responseData;
                }

                // Should never reach here due to PostConstruct check, but safe fallback
                throw new IllegalStateException("No authentication mechanism enabled.");
            }
        }

        responseData.put("message", "INVALID_CREDENTIALS");
        return responseData;
    }


    public Map<String, String> refreshAccessToken(String refreshToken, HttpServletResponse response) {
        if (!authCoreConfig.getRefreshToken().isEnabled()) {
            throw new UnsupportedOperationException("Refresh token is disabled.");
        }

        if (!authCoreConfig.getJwt().isEnabled()) {
            throw new IllegalStateException("JWT is disabled. Cannot refresh token.");
        }

        Map<String, String> responseData = new HashMap<>();
        String username = jwtUtil.extractUsername(refreshToken);

        if (!jwtUtil.validateToken(refreshToken, username)) {
            throw new IllegalArgumentException("Invalid refresh token");
        }

        Optional<UserDetails> userOpt = Optional.ofNullable(userService.loadUserByUsername(username));
        if (userOpt.isEmpty()) {
            throw new IllegalArgumentException("User not found for refresh token");
        }

        UserDetails user = userOpt.get();
        String newAccessToken = jwtUtil.generateAccessToken(username, claimsProvider.
                extractClaims(user));
        responseData.put("accessToken", newAccessToken);

        if (authCoreConfig.getRefreshToken().isEnabled()) {
            String newRefreshToken = jwtUtil.generateRefreshToken(username);
            responseData.put("refreshToken", newRefreshToken);

            if (authCoreConfig.getCookies().isEnabled()) {
                setCookie(response, authCoreConfig.getCookies().getName(), newRefreshToken, authCoreConfig.getCookies().getMaxAge());
            }
        }

        return responseData;
    }

    public Map<String, String> logout(HttpServletResponse response) {
        clearCookie(response, authCoreConfig.getCookies().getName());

        Map<String, String> responseData = new HashMap<>();
        responseData.put("message", "LOGOUT_SUCCESS");

        logger.info("User logged out.");
        return responseData;
    }

    private void setCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(authCoreConfig.getCookies().isHttpOnly());
        cookie.setSecure(authCoreConfig.getCookies().isSecure());
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        response.addCookie(cookie);
    }

    private void clearCookie(HttpServletResponse response, String name) {
        Cookie cookie = new Cookie(name, null);
        cookie.setHttpOnly(authCoreConfig.getCookies().isHttpOnly());
        cookie.setSecure(authCoreConfig.getCookies().isSecure());
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }
}
