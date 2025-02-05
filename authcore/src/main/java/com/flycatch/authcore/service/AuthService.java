package com.flycatch.authcore.service;

import com.flycatch.authcore.config.AuthCoreConfig;
import com.flycatch.authcore.model.User;
import com.flycatch.authcore.repository.UserRepository;
import com.flycatch.authcore.util.JwtUtil;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
public class AuthService {

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
        Optional<User> userOpt = userRepository.findByUsername(username);

        Map<String, String> response = new HashMap<>();
        if (userOpt.isPresent() && passwordEncoder.matches(password, userOpt.get().getPassword())) {
            response.put("accessToken", jwtUtil.generateAccessToken(username));

            if (authCoreConfig.isEnableRefreshToken()) {
                response.put("refreshToken", jwtUtil.generateRefreshToken(username));
            }
            response.put("message", "JWT_AUTHENTICATED");
        } else {
            response.put("message", "INVALID_CREDENTIALS");
        }
        return response;
    }

    public Map<String, String> register(String username, String password) {
        Map<String, String> response = new HashMap<>();

        if (userRepository.findByUsername(username).isPresent()) {
            response.put("message", "USER_ALREADY_EXISTS");
            return response;
        }

        User user = new User(username, passwordEncoder.encode(password));
        userRepository.save(user);
        response.put("message", "USER_REGISTERED_SUCCESSFULLY");
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

        return jwtUtil.generateAccessToken(username);
    }
}
