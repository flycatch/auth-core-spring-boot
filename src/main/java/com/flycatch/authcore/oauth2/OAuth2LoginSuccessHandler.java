package com.flycatch.authcore.oauth2;

import com.flycatch.authcore.config.AuthCoreConfig;
import com.flycatch.authcore.rbac.RbacAuthorityService;
import com.flycatch.authcore.security.AuthConstants;
import com.flycatch.authcore.spi.JwtClaimsProvider;
import com.flycatch.authcore.util.JwtUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

@Component
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private static final Logger log = LoggerFactory.getLogger(OAuth2LoginSuccessHandler.class);

    private final JwtUtil jwtUtil;
    private final AuthCoreConfig cfg;
    private final JwtClaimsProvider claimsProvider;
    private final RbacAuthorityService rbac;

    public OAuth2LoginSuccessHandler(
            JwtUtil jwtUtil,
            AuthCoreConfig cfg,
            JwtClaimsProvider claimsProvider,
            RbacAuthorityService rbac
    ) {
        this.jwtUtil = jwtUtil;
        this.cfg = cfg;
        this.claimsProvider = claimsProvider;
        this.rbac = rbac;
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            org.springframework.security.core.Authentication authentication
    ) throws IOException, ServletException {

        if (!(authentication instanceof OAuth2AuthenticationToken oauthToken)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid OAuth2 authentication");
            return;
        }

        OAuth2User oauth2User = oauthToken.getPrincipal();
        String registrationId = oauthToken.getAuthorizedClientRegistrationId(); // e.g., google, github

        // Derive a stable username (email if available, else provider:id)
        String email = firstNonBlank(
                get(oauth2User, "email"),
                get(oauth2User, "email_address"),
                get(oauth2User, "preferred_username")
        );
        String sub = firstNonBlank(
                get(oauth2User, "sub"),
                get(oauth2User, "id"),
                get(oauth2User, "user_id")
        );
        String login = get(oauth2User, "login"); // GitHub

        String username = firstNonBlank(email, login, (registrationId + ":" + (sub != null ? sub : UUID.randomUUID())));

        // Base authorities from the OAuth2 authentication
        Set<String> baseAuthorities = oauthToken.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toCollection(LinkedHashSet::new));

        // Expand ROLE_* to permissions using your RBAC map
        Set<String> expandedAuthorities = rbac.expandAuthorities(baseAuthorities);

        // Prepare JWT claims
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("provider", registrationId);
        claims.put("subject", sub);
        claims.put("email", email);
        claims.put("login", login);

        if (cfg.getOauth2().isIncludeAuthorities()) {
            List<String> authorities = expandedAuthorities.stream().sorted().toList();
            claims.put(AuthConstants.CLAIM_AUTHORITIES, authorities);
            List<String> roles = authorities.stream().filter(a -> a.startsWith("ROLE_")).toList();
            claims.put(AuthConstants.CLAIM_ROLES, roles);
        }

        // >>> FIX: pass a real UserDetails (not a lambda) to claimsProvider
        if (claimsProvider != null) {
            try {
                UserDetails synthetic = buildUserDetails(username, expandedAuthorities);
                Map<String, Object> extra = claimsProvider.extractClaims(synthetic);
                if (extra != null) claims.putAll(extra);
            } catch (Exception ignored) {
            }
        }

        String accessToken = null;
        String refreshToken = null;

        if (cfg.getOauth2().isIssueJwt() && cfg.getJwt().isEnabled()) {
            accessToken = jwtUtil.generateAccessToken(username, claims);

            if (cfg.getJwt().isRefreshTokenEnabled()) {
                refreshToken = jwtUtil.generateRefreshToken(username);
            }
        }

        // Optionally set refresh cookie (if cookies + property enabled)
        if (refreshToken != null
                && cfg.getCookies().isEnabled()
                && cfg.getOauth2().isSetRefreshCookie()) {

            ResponseCookie c = ResponseCookie.from(cfg.getCookies().getName(), refreshToken)
                    .httpOnly(cfg.getCookies().isHttpOnly())
                    .secure(cfg.getCookies().isSecure())
                    .sameSite(cfg.getCookies().getSameSite())
                    .path("/")
                    .maxAge(Duration.ofSeconds(cfg.getCookies().getMaxAge()))
                    .build();
            response.addHeader("Set-Cookie", c.toString());
        }

        // Build success redirect URL with query params
        UriComponentsBuilder b = UriComponentsBuilder.fromUriString(cfg.getOauth2().getSuccessRedirect());

        if (accessToken != null) {
            b.queryParam(cfg.getOauth2().getAccessTokenParam(), accessToken);
        }
        if (refreshToken != null) {
            b.queryParam(cfg.getOauth2().getRefreshTokenParam(), refreshToken);
        }
        b.queryParam("provider", registrationId);

        URI redirect = b.build(true).toUri();

        if (cfg.getLogging().isEnabled()) {
            log.info("OAuth2 success for '{}', provider='{}' → redirecting to {}", username, registrationId, redirect);
        }

        response.setStatus(HttpServletResponse.SC_FOUND);
        response.setHeader("Location", redirect.toString());
    }

    private static String get(OAuth2User user, String key) {
        Object v = user.getAttributes().get(key);
        return v == null ? null : String.valueOf(v);
    }

    private static String firstNonBlank(String... vals) {
        for (String v : vals) {
            if (v != null && !v.isBlank()) return v;
        }
        return null;
    }

    private static UserDetails buildUserDetails(String username, Collection<String> authorities) {
        String[] authArray = authorities == null ? new String[0] : authorities.toArray(String[]::new);
        return User.withUsername(username)
                .password("{noop}OAUTH2") // not used; avoids encoder complaints
                .authorities(authArray)
                .accountExpired(false).accountLocked(false).credentialsExpired(false).disabled(false)
                .build();
    }
}
