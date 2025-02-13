package com.flycatch.authcore.service;

import com.flycatch.authcore.config.AuthCoreConfig;
import com.flycatch.authcore.model.User;
import com.flycatch.authcore.repository.UserRepository;
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

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthCoreConfig authCoreConfig;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtUtil jwtUtil, AuthCoreConfig authCoreConfig) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.authCoreConfig = authCoreConfig;
    }

    /**
     * Authenticate a user and generate JWT tokens.
     */
    public Map<String, String> authenticate(String username, String password, HttpServletResponse response) {
        if (authCoreConfig.isEnableLogging()) {
            logger.info("Authenticating user: {}", username);
        }

        Optional<User> userOpt = userRepository.findByUsername(username);
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

            if (authCoreConfig.isEnableLogging()) {
                logger.info("User '{}' authenticated successfully.", username);
            }
        } else {
            responseData.put("message", "INVALID_CREDENTIALS");

            if (authCoreConfig.isEnableLogging()) {
                logger.warn("Authentication failed for user: {}", username);
            }
        }
        return responseData;
    }

    /**
     * Register a new user.
     */
    public Map<String, String> register(String username, String password) {
        if (authCoreConfig.isEnableLogging()) {
            logger.info("Registering new user: {}", username);
        }

        Map<String, String> response = new HashMap<>();

        if (userRepository.findByUsername(username).isPresent()) {
            response.put("message", "USER_ALREADY_EXISTS");

            if (authCoreConfig.isEnableLogging()) {
                logger.warn("Registration failed: User '{}' already exists.", username);
            }
            return response;
        }

        User user = new User(username, passwordEncoder.encode(password));
        userRepository.save(user);
        response.put("message", "USER_REGISTERED_SUCCESSFULLY");

        if (authCoreConfig.isEnableLogging()) {
            logger.info("User '{}' registered successfully.", username);
        }

        return response;
    }

    /**
     * Refresh access token using a valid refresh token.
     */
    public Map<String, String> refreshAccessToken(String refreshToken, HttpServletResponse response) {
        if (!authCoreConfig.isEnableRefreshToken()) {
            throw new UnsupportedOperationException("Refresh token functionality is disabled.");
        }

        Map<String, String> responseData = new HashMap<>();
        String username = jwtUtil.extractUsername(refreshToken);

        if (!jwtUtil.validateToken(refreshToken, username)) {
            throw new IllegalArgumentException("Invalid refresh token");
        }

        if (authCoreConfig.isEnableLogging()) {
            logger.info("Refreshing access token for user: {}", username);
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

    /**
     * Logout and clear refresh token cookie.
     */
    public Map<String, String> logout(HttpServletResponse response) {
        if (authCoreConfig.isEnableLogging()) {
            logger.info("Logging out user. Clearing authentication cookies.");
        }

        clearCookie(response, authCoreConfig.getCookieName());

        Map<String, String> responseData = new HashMap<>();
        responseData.put("message", "LOGOUT_SUCCESS");

        return responseData;
    }

    /**
     * Set a secure HTTP-only cookie for storing refresh tokens.
     */
    private void setCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(authCoreConfig.isCookieHttpOnly());
        cookie.setSecure(authCoreConfig.isCookieSecure());
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        response.addCookie(cookie);

        if (authCoreConfig.isEnableLogging()) {
            logger.info("Cookie '{}' set with expiration time: {} seconds", name, maxAge);
        }
    }

    /**
     * Clear an authentication cookie.
     */
    private void clearCookie(HttpServletResponse response, String name) {
        Cookie cookie = new Cookie(name, null);
        cookie.setHttpOnly(authCoreConfig.isCookieHttpOnly());
        cookie.setSecure(authCoreConfig.isCookieSecure());
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);

        if (authCoreConfig.isEnableLogging()) {
            logger.info("Cookie '{}' cleared on logout.", name);
        }
    }
}
