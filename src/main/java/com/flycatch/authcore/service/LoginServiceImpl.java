package com.flycatch.authcore.service;

import com.flycatch.authcore.spi.JwtClaimsProvider;
import com.flycatch.authcore.util.JwtUtil;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LoginServiceImpl  {
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final JwtClaimsProvider claimsProvider;

    public String login(String username, String password,HttpServletResponse response) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        return jwtUtil.generateAccessToken(
                userDetails.getUsername(),
                claimsProvider != null ? claimsProvider.extractClaims(userDetails) : null
        );
    }

}
