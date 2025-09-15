package com.flycatch.authcore.oauth2;

import com.flycatch.authcore.config.AuthCoreConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;

@Component
public class OAuth2LoginFailureHandler implements AuthenticationFailureHandler {

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
        URI redirect = UriComponentsBuilder.fromUriString(cfg.getOauth2().getFailureRedirect())
                .queryParam("reason", reason)
                .build(true)
                .toUri();

        response.setStatus(HttpServletResponse.SC_FOUND);
        response.setHeader("Location", redirect.toString());
    }
}
