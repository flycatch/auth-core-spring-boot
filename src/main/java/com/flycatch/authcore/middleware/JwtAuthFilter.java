package com.flycatch.authcore.middleware;

import com.flycatch.authcore.config.AuthCoreConfig;
import com.flycatch.authcore.spi.JwtClaimsProvider;
import com.flycatch.authcore.util.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Map;

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
                Map<String, Object> claims = jwtUtil.extractAllClaims(token);

                if (authCoreConfig.getLogging().isEnabled()) {
                    logger.info("Processing JWT token for user: {}", username);
                }

                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    if (jwtUtil.validateToken(token, username)) {
                       // Collection<? extends GrantedAuthority> authorities = claimsProvider.extractAuthorities(claims);

                        UsernamePasswordAuthenticationToken authentication =
                                new UsernamePasswordAuthenticationToken(username, null, null);

                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authentication);

                        if (authCoreConfig.getLogging().isEnabled()) {
                            logger.info("User '{}' authenticated via JWT", username);
                        }
                    }
                }

            } catch (ExpiredJwtException e) {
                if (authCoreConfig.getLogging().isEnabled()) {
                    logger.warn("JWT token expired for user: {}", e.getClaims().getSubject());
                }
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token Expired");
                return;
            } catch (Exception e) {
                if (authCoreConfig.getLogging().isEnabled()) {
                    logger.error("JWT processing failed: {}", e.getMessage());
                }
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid Token");
                return;
            }
        }

        chain.doFilter(request, response);
    }
}
