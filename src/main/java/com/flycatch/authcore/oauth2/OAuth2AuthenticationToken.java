package com.flycatch.authcore.oauth2;

import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class OAuth2AuthenticationToken extends AbstractAuthenticationToken {
    @Getter
    private final String provider;
    private final String principalEmail;
    @Getter
    private final String accessToken;

    public OAuth2AuthenticationToken(
            String provider,
            String email,
            String accessToken,
            Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.provider = provider;
        this.principalEmail = email;
        this.accessToken = accessToken;
        setAuthenticated(true);
    }
    @Override
    public Object getCredentials() {
        return accessToken;
    }

    @Override
    public Object getPrincipal() {
        return principalEmail;
    }

}
