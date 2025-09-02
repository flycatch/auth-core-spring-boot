package com.flycatch.authcore.middleware;

import com.flycatch.authcore.config.AuthCoreConfig;
import com.flycatch.authcore.rbac.RbacAuthorityService;
import com.flycatch.authcore.security.AuthConstants;
import com.flycatch.authcore.util.JwtUtil;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Stateless JWT auth filter. Skips /auth/** so white-label endpoints are publicly accessible.
 * PRESERVED: logging, /auth/** bypass, error handling.
 * ENHANCED: restore authorities from JWT (authorities claim) or fallback to DB + YAML expansion.
 */
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthFilter.class);

    private final JwtUtil jwtUtil;
    private final AuthCoreConfig cfg;
    private final UserDetailsService userDetailsService;
    private final RbacAuthorityService rbac;

    public JwtAuthFilter(JwtUtil jwtUtil,
                         AuthCoreConfig cfg,
                         UserDetailsService userDetailsService,
                         RbacAuthorityService rbac) {
        this.jwtUtil = jwtUtil;
        this.cfg = cfg;
        this.userDetailsService = userDetailsService;
        this.rbac = rbac;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
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

                    boolean valid = jwtUtil.validateToken(token, username);
                    if (valid) {
                        // Prefer authorities embedded in token
                        List<SimpleGrantedAuthority> authoritiesFromToken = extractAuthorities(token);

                        UsernamePasswordAuthenticationToken authentication;
                        if (!authoritiesFromToken.isEmpty()) {
                            authentication = new UsernamePasswordAuthenticationToken(username, null, authoritiesFromToken);
                        } else {
                            // Back-compat fallback: load from DB and expand ROLE_* via YAML
                            var user = userDetailsService.loadUserByUsername(username);
                            var base = user.getAuthorities().stream()
                                    .map(a -> a.getAuthority())
                                    .collect(Collectors.toSet());
                            var expanded = rbac.expandAuthorities(base);
                            var auths = expanded.stream().map(SimpleGrantedAuthority::new).toList();
                            authentication = new UsernamePasswordAuthenticationToken(username, null, auths);
                        }

                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));
                        SecurityContextHolder.getContext().setAuthentication(authentication);

                        if (cfg.getLogging().isEnabled()) {
                            log.info("User '{}' authenticated via JWT with {} authorities",
                                    username, authentication.getAuthorities().size());
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

    @SuppressWarnings("unchecked")
    private List<SimpleGrantedAuthority> extractAuthorities(String token) {
        try {
            Map<String, Object> claims = jwtUtil.extractAllClaims(token);
            Object raw = claims.get(AuthConstants.CLAIM_AUTHORITIES);
            if (raw instanceof Collection<?> col) {
                return col.stream()
                        .map(Object::toString)
                        .filter(s -> !s.isBlank())
                        .distinct()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());
            }
        } catch (Exception ignored) { }
        return Collections.emptyList();
    }
}
