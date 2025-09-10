package com.flycatch.authcore.oauth2;

import com.flycatch.authcore.service.AuthService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {
    private final AuthService authService;
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // Spring injects OAuth2User on successful login
        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();

        // Get the email (Google, GitHub, etc.)
        String email = oauth2User.getAttribute("email");

        // Delegate to AuthService → issues JWT or Session
        Map<String, String> tokens = authService.authenticateOAuth2(email, request, response);

        // Write response JSON with tokens
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        StringBuilder json = new StringBuilder("{");
        tokens.forEach((k, v) -> json.append("\"").append(k).append("\":\"").append(v).append("\","));
        if (!tokens.isEmpty()) json.setLength(json.length() - 1); // remove trailing comma
        json.append("}");

        response.getWriter().write(json.toString());
    }
    }

