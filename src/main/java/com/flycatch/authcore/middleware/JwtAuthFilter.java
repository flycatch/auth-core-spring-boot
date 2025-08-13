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
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Stateless JWT auth filter. Skips /auth/** so white-label endpoints are publicly accessible.
 */
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthFilter.class);

    private final JwtUtil jwtUtil;
    private final AuthCoreConfig cfg;

    public JwtAuthFilter(JwtUtil jwtUtil, AuthCoreConfig cfg) {
        this.jwtUtil = jwtUtil;
        this.cfg = cfg;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        return path.startsWith("/auth");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {

        String authHeader = req.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);

            try {
                String username = jwtUtil.extractUsername(token);

                if (cfg.getLogging().isEnabled()) {
                    log.info("Processing JWT for user: {}", username);
                }

                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    if (jwtUtil.validateToken(token, username)) {
                        UsernamePasswordAuthenticationToken authentication =
                                new UsernamePasswordAuthenticationToken(username, null, null);
                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));
                        SecurityContextHolder.getContext().setAuthentication(authentication);

                        if (cfg.getLogging().isEnabled()) {
                            log.info("User '{}' authenticated via JWT", username);
                        }
                    }
                }

            } catch (ExpiredJwtException e) {
                if (cfg.getLogging().isEnabled()) {
                    log.warn("JWT token expired for user: {}", e.getClaims().getSubject());
                }
                res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token Expired");
                return;
            } catch (Exception e) {
                if (cfg.getLogging().isEnabled()) {
                    log.error("JWT processing failed: {}", e.getMessage());
                }
                res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid Token");
                return;
            }
        }

        chain.doFilter(req, res);
    }
}
