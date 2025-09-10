package com.flycatch.authcore.service;

import com.flycatch.authcore.config.AuthCoreConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class OAuth2ClientService {
    private final AuthCoreConfig config;
    private final RestTemplate restTemplate;
    public String buildAuthorizeUrl(String provider, String state) {
        var p = cfg(provider);
        String scope = String.join(" ", p.getScopes());
        return p.getAuthUri() + "?" + params(Map.of(
                "client_id", p.getClientId(),
                "redirect_uri", p.getRedirectUri(),
                "scope", scope,
                "state", state
        ));

}
    private AuthCoreConfig.Provider cfg(String provider) {
        var p = config.getOauth2().getProviders().get(provider);
        if (p == null) throw new IllegalArgumentException("Unknown OAuth2 provider: " + provider);
        return p;
    }

    private static String params(Map<String, String> map) {
        return map.entrySet().stream()
                .map(e -> enc(e.getKey()) + "=" + enc(e.getValue()))
                .collect(Collectors.joining("&"));
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

}
