package com.flycatch.authcore.spi;

import java.util.*;

public interface UserProvisioner {

    /**
     * Called on EACH successful OAuth2 login.
     * Implementations must be IDEMPOTENT: create user if absent, otherwise return existing.
     * Return ROLE_* and/or permission authorities to embed in the JWT.
     */
    ProvisionResult provisionIfAbsent(OAuth2UserProfile profile);

    final class ProvisionResult {
        private final boolean created;
        private final Set<String> authorities;

        public ProvisionResult(boolean created, Set<String> authorities) {
            this.created = created;
            this.authorities = authorities == null ? Collections.emptySet() : new LinkedHashSet<>(authorities);
        }
        public boolean isCreated() { return created; }
        public Set<String> getAuthorities() { return authorities; }

        public static ProvisionResult createdWithAuthorities(Set<String> authorities) {
            return new ProvisionResult(true, authorities);
        }
        public static ProvisionResult existsWithAuthorities(Set<String> authorities) {
            return new ProvisionResult(false, authorities);
        }
        public static ProvisionResult noop() { return new ProvisionResult(false, Collections.emptySet()); }
    }

    final class OAuth2UserProfile {
        private final String provider;   // e.g., "google"
        private final String subject;    // provider's user id (sub)
        private final String username;   // your app's principal (email preferred)
        private final String email;      // may be null
        private final String login;      // e.g., GitHub login; may be null
        private final Map<String, Object> attributes;

        public OAuth2UserProfile(String provider, String subject, String username, String email,
                                 String login, Map<String, Object> attributes) {
            this.provider = provider;
            this.subject = subject;
            this.username = username;
            this.email = email;
            this.login = login;
            this.attributes = attributes == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(attributes));
        }
        public String getProvider() { return provider; }
        public String getSubject() { return subject; }
        public String getUsername() { return username; }
        public String getEmail() { return email; }
        public String getLogin() { return login; }
        public Map<String, Object> getAttributes() { return attributes; }
    }
}
