package com.flycatch.authcore.service;

import com.flycatch.authcore.config.AuthCoreConfig;
import com.flycatch.authcore.model.AuthCoreUser;
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

    public AuthService(AuthCoreUserService userService, PasswordEncoder passwordEncoder, JwtUtil jwtUtil, AuthCoreConfig authCoreConfig) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.authCoreConfig = authCoreConfig;
    }

    public Map<String, String> authenticate(String username, String password, HttpServletResponse response) {
        if (authCoreConfig.isEnableLogging()) {
            logger.info("Authenticating user: {}", username);
        }

        Optional<? extends AuthCoreUser> userOpt = userService.findByUsername(username);
        Map<String, String> responseData = new HashMap<>();

        if (userOpt.isPresent() && passwordEncoder.matches(password, userOpt.get().getPassword())) {
            String accessToken = jwtUtil.generateAccessToken(username);
            responseData.put("accessToken", accessToken);

            if (authCoreConfig.isEnableRefreshToken()) {
                String refreshToken = jwtUtil.generateRefreshToken(username);
                responseData.put("refreshToken", refreshToken);

                if (authCoreConfig.isEnableCookies()) {
                    setCookie(response, authCoreConfig.getCookieName(), refreshToken, authCoreConfig.getCookieMaxAge());
                }
            }

            responseData.put("message", "JWT_AUTHENTICATED");
            logger.info("User '{}' authenticated successfully.", username);
        } else {
            responseData.put("message", "INVALID_CREDENTIALS");
            logger.warn("Authentication failed for user: {}", username);
        }

        return responseData;
    }

    public Map<String, String> register(String username, String password) {
        if (authCoreConfig.isEnableLogging()) {
            logger.info("Registering user: {}", username);
        }

        Map<String, String> response = new HashMap<>();

        if (userService.findByUsername(username).isPresent()) {
            response.put("message", "USER_ALREADY_EXISTS");
            logger.warn("User '{}' already exists.", username);
            return response;
        }

        userService.save(username, passwordEncoder.encode(password));
        response.put("message", "USER_REGISTERED_SUCCESSFULLY");
        logger.info("User '{}' registered.", username);

        return response;
    }

    public Map<String, String> refreshAccessToken(String refreshToken, HttpServletResponse response) {
        if (!authCoreConfig.isEnableRefreshToken()) {
            throw new UnsupportedOperationException("Refresh token is disabled.");
        }

        Map<String, String> responseData = new HashMap<>();
        String username = jwtUtil.extractUsername(refreshToken);

        if (!jwtUtil.validateToken(refreshToken, username)) {
            throw new IllegalArgumentException("Invalid refresh token");
        }

        String newAccessToken = jwtUtil.generateAccessToken(username);
        responseData.put("accessToken", newAccessToken);

        if (authCoreConfig.isEnableRefreshToken()) {
            String newRefreshToken = jwtUtil.generateRefreshToken(username);
            responseData.put("refreshToken", newRefreshToken);

            if (authCoreConfig.isEnableCookies()) {
                setCookie(response, authCoreConfig.getCookieName(), newRefreshToken, authCoreConfig.getCookieMaxAge());
            }
        }

        return responseData;
    }

    public Map<String, String> logout(HttpServletResponse response) {
        clearCookie(response, authCoreConfig.getCookieName());

        Map<String, String> responseData = new HashMap<>();
        responseData.put("message", "LOGOUT_SUCCESS");

        logger.info("User logged out.");
        return responseData;
    }

    private void setCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(authCoreConfig.isCookieHttpOnly());
        cookie.setSecure(authCoreConfig.isCookieSecure());
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        response.addCookie(cookie);
    }

    private void clearCookie(HttpServletResponse response, String name) {
        Cookie cookie = new Cookie(name, null);
        cookie.setHttpOnly(authCoreConfig.isCookieHttpOnly());
        cookie.setSecure(authCoreConfig.isCookieSecure());
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }
}
