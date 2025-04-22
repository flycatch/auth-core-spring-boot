package com.flycatch.authcore.middleware;

import com.flycatch.authcore.config.AuthCoreConfig;
import com.flycatch.authcore.util.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthFilter.class);

    private final JwtUtil jwtUtil;
    private final AuthCoreConfig authCoreConfig;

    public JwtAuthFilter(JwtUtil jwtUtil, AuthCoreConfig authCoreConfig) {
        this.jwtUtil = jwtUtil;
        this.authCoreConfig = authCoreConfig;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        // Skip the filter for any /auth endpoints
        String path = request.getRequestURI();
        return path.startsWith("/auth");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String token = request.getHeader("Authorization");

        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);

            try {
                String username = jwtUtil.extractUsername(token);

                if (authCoreConfig.isEnableLogging()) {
                    logger.info("Processing JWT token for user: {}", username);
                }

                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    UserDetails userDetails = new User(username, "", Collections.emptyList());

                    if (jwtUtil.validateToken(token, username)) {
                        UsernamePasswordAuthenticationToken authentication =
                                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authentication);

                        if (authCoreConfig.isEnableLogging()) {
                            logger.info("User '{}' authenticated via JWT", username);
                        }
                    }
                }
            } catch (ExpiredJwtException e) {
                if (authCoreConfig.isEnableLogging()) {
                    logger.warn("JWT token expired for user: {}", e.getClaims().getSubject());
                }
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token Expired");
                return;
            }
        }

        chain.doFilter(request, response);
    }
}
