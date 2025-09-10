package com.flycatch.authcore.oauth2;

import com.flycatch.authcore.config.AuthCoreConfig;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

@Component
public class ClientRegistrationFactory {
    private final AuthCoreConfig cfg;

    public ClientRegistrationFactory(AuthCoreConfig cfg) {
        this.cfg = cfg;
    }

    public ClientRegistrationRepository buildRepository() {
        Map<String, AuthCoreConfig.Provider> providers = cfg.getOauth2().getProviders();

        List<ClientRegistration> registrations = providers.entrySet().stream()
                .map(entry -> buildClient(entry.getKey(), entry.getValue()))
                .toList();

        return new InMemoryClientRegistrationRepository(registrations);
    }

    private ClientRegistration buildClient(String id, AuthCoreConfig.Provider provider) {
        return ClientRegistration.withRegistrationId(id)
                .clientId(provider.getClientId())
                .clientSecret(provider.getClientSecret())
                .redirectUri(provider.getRedirectUri())
                .scope(provider.getScopes())
                .authorizationUri(provider.getAuthorizationUri())
                .tokenUri(provider.getTokenUri())
                .userInfoUri(provider.getUserInfoUri())
                .userNameAttributeName(provider.getUserNameAttribute())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .clientName(id)
                .build();
    }
}
