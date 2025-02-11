package com.flycatch.authcore.service;

import com.flycatch.authcore.config.AuthCoreConfig;
import com.flycatch.authcore.model.User;
import com.flycatch.authcore.repository.UserRepository;
import com.flycatch.authcore.util.JwtUtil;
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

    public Map<String, String> authenticate(String username, String password) {
        if (authCoreConfig.isEnableLogging()) {
            logger.info("Attempting authentication for user: {}", username);
        }

        Optional<User> userOpt = userRepository.findByUsername(username);
        Map<String, String> response = new HashMap<>();

        if (userOpt.isPresent() && passwordEncoder.matches(password, userOpt.get().getPassword())) {
            String accessToken = jwtUtil.generateAccessToken(username);
            response.put("accessToken", accessToken);

            if (authCoreConfig.isEnableRefreshToken()) {
                response.put("refreshToken", jwtUtil.generateRefreshToken(username));
            }

            response.put("message", "JWT_AUTHENTICATED");

            if (authCoreConfig.isEnableLogging()) {
                logger.info("User '{}' authenticated successfully.", username);
            }
        } else {
            response.put("message", "INVALID_CREDENTIALS");

            if (authCoreConfig.isEnableLogging()) {
                logger.warn("Authentication failed for user: {}", username);
            }
        }
        return response;
    }

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

    public String refreshAccessToken(String refreshToken) {
        if (!authCoreConfig.isEnableRefreshToken()) {
            throw new UnsupportedOperationException("Refresh token functionality is disabled.");
        }

        String username = jwtUtil.extractUsername(refreshToken);

        if (!jwtUtil.validateToken(refreshToken, username)) {
            throw new IllegalArgumentException("Invalid refresh token");
        }

        if (authCoreConfig.isEnableLogging()) {
            logger.info("Refreshing access token for user: {}", username);
        }

        return jwtUtil.generateAccessToken(username);
    }
}
