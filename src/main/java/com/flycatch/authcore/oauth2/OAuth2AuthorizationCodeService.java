package com.flycatch.authcore.oauth2;

import com.flycatch.authcore.config.AuthCoreConfig;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class OAuth2AuthorizationCodeService {

    private final AuthCoreConfig cfg;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, CodeEntry> store = new ConcurrentHashMap<>();

    public OAuth2AuthorizationCodeService(AuthCoreConfig cfg) {
        this.cfg = cfg;
    }

    /**
     * Generate a short-lived authorization code for the given username.
     */
    public String createCode(String username) {
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("username is required to create authorization code");
        }

        int length = Math.max(16, cfg.getOauth2().getCodeLength());
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(alphabet.charAt(random.nextInt(alphabet.length())));
        }
        String code = sb.toString();

        long ttl = cfg.getOauth2().getCodeTtlSeconds();
        if (ttl <= 0) {
            ttl = 300L;
        }

        Instant expiresAt = Instant.now().plusSeconds(ttl);
        store.put(code, new CodeEntry(username, expiresAt));

        return code;
    }

    /**
     * Consume the code (one-time). Returns username if valid, null otherwise.
     */
    public String consumeCode(String code) {
        if (code == null) {
            return null;
        }
        String key = code.trim();
        if (key.isEmpty()) {
            return null;
        }

        CodeEntry entry = store.remove(key);
        if (entry == null) {
            return null;
        }
        if (Instant.now().isAfter(entry.expiresAt())) {
            return null;
        }
        return entry.username();
    }

    private record CodeEntry(String username, Instant expiresAt) {}
}
