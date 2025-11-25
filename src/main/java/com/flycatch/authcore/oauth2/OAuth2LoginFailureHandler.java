package com.flycatch.authcore.oauth2;

import com.flycatch.authcore.config.AuthCoreConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;

@Component
public class OAuth2LoginFailureHandler implements AuthenticationFailureHandler {

    private static final Logger log = LoggerFactory.getLogger(OAuth2LoginFailureHandler.class);

    private final AuthCoreConfig cfg;

    public OAuth2LoginFailureHandler(AuthCoreConfig cfg) {
        this.cfg = cfg;
    }

    @Override
    public void onAuthenticationFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            org.springframework.security.core.AuthenticationException exception
    ) throws IOException, ServletException {

        String reason = exception.getClass().getSimpleName();

        if (cfg.getLogging().isEnabled()) {
            log.warn("OAuth2 authentication failure: {} - {}", reason, exception.getMessage());
        }

        // Client only sees generic error
        URI redirect = UriComponentsBuilder.fromUriString(cfg.getOauth2().getFailureRedirect())
                .queryParam("error", "UNAUTHORIZED")
                .build(true)
                .toUri();

        response.setStatus(HttpServletResponse.SC_FOUND);
        response.setHeader("Location", redirect.toString());
    }
}
