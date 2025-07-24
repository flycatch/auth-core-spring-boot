package com.flycatch.authcore.service;

import com.flycatch.authcore.config.AuthCoreConfig;
import com.flycatch.authcore.spi.JwtClaimsProvider;
import com.flycatch.authcore.util.JwtUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
public class AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

    private final AuthCoreUserService userService;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthCoreConfig authCoreConfig;
    private final JwtClaimsProvider claimsProvider;

    public AuthService(AuthCoreUserService userService, PasswordEncoder passwordEncoder, JwtUtil jwtUtil,
                       AuthCoreConfig authCoreConfig, JwtClaimsProvider claimsProvider) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.authCoreConfig = authCoreConfig;
        this.claimsProvider = claimsProvider;
    }

    public Map<String, String> authenticate(String loginId, String password, HttpServletResponse response) {
        if (authCoreConfig.getLogging().isEnabled()) {
            logger.info("Authenticating user: {}", loginId);
        }

        Optional<Object> userOpt = loginId.contains("@") ? userService.findByEmail(loginId) : userService.findByUsername(loginId);
        Map<String, String> responseData = new HashMap<>();

        if (userOpt.isPresent()) {
            Object user = userOpt.get();
            String storedPassword = claimsProvider.extractPassword(user);
            String username = claimsProvider.extractUsername(user);

            if (passwordEncoder.matches(password, storedPassword)) {
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
        }
        responseData.put("message", "INVALID_CREDENTIALS");
        return responseData;
    }

    public Map<String, String> register(String username, String email, String password) {
        if (authCoreConfig.getLogging().isEnabled()) {
            logger.info("Registering user: username={}, email={}", username, email);
        }

        Map<String, String> response = new HashMap<>();

        boolean usernameExists = username != null && userService.findByUsername(username).isPresent();
        boolean emailExists = email != null && userService.findByEmail(email).isPresent();

        if (usernameExists || emailExists) {
            response.put("message", "USER_ALREADY_EXISTS");
            return response;
        }

        userService.save(username, email, passwordEncoder.encode(password));
        response.put("message", "USER_REGISTERED_SUCCESSFULLY");
        return response;
    }

    public Map<String, String> refreshAccessToken(String refreshToken, HttpServletResponse response) {
        if (!authCoreConfig.getRefreshToken().isEnabled()) {
            throw new UnsupportedOperationException("Refresh token is disabled.");
        }

        Map<String, String> responseData = new HashMap<>();
        String username = jwtUtil.extractUsername(refreshToken);

        if (!jwtUtil.validateToken(refreshToken, username)) {
            throw new IllegalArgumentException("Invalid refresh token");
        }

        Optional<Object> userOpt = userService.findByUsername(username);
        if (userOpt.isEmpty()) {
            throw new IllegalArgumentException("User not found for refresh token");
        }

        Object user = userOpt.get();
        String newAccessToken = jwtUtil.generateAccessToken(username, claimsProvider.extractClaims(user));
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
