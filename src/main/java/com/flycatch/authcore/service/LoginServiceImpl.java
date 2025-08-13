package com.flycatch.authcore.service;

import com.flycatch.authcore.spi.JwtClaimsProvider;
import com.flycatch.authcore.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class LoginServiceImpl implements LoginService {
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final JwtClaimsProvider claimsProvider;

    public String login(String username, String password,HttpServletResponse response) {
        // Step 1: Authenticate credentials
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        // Step 2: Get authenticated user details
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        // Step 3: Generate JWT access token
        return jwtUtil.generateAccessToken(
                userDetails.getUsername(),
                claimsProvider != null ? claimsProvider.extractClaims(userDetails) : null
        );
    }

}
