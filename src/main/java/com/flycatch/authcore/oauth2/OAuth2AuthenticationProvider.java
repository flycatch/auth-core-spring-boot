package com.flycatch.authcore.oauth2;

import com.flycatch.authcore.config.AuthCoreConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;

@RequiredArgsConstructor
@ConditionalOnProperty(prefix = "auth.oauth2", name = "enabled", havingValue = "true")
@Component
public class OAuth2AuthenticationProvider implements AuthenticationProvider {
    private final AuthCoreConfig config;
    private final RestTemplate restTemplate = new RestTemplate();
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!(authentication instanceof OAuth2AuthenticationToken token)) return null;

        var providerCfg = config.getOauth2().getProviders().get(token.getProvider());
        if (providerCfg == null) return null;

        // Validate token by calling userinfo endpoint
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(String.valueOf(token.getCredentials()));
        HttpEntity<Void> entity = new HttpEntity<>(headers);

        ResponseEntity<Map> resp = restTemplate.exchange(
                providerCfg.getUserInfoUri(), HttpMethod.GET, entity, Map.class
        );
        Map userInfo = resp.getBody();
        String email = userInfo != null ? (String) userInfo.getOrDefault("email", token.getPrincipal()) : (String) token.getPrincipal();

        return new OAuth2AuthenticationToken(
                token.getProvider(),
                email,
                token.getAccessToken(),
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return false;
    }
}
