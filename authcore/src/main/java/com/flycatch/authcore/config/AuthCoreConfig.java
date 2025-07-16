package com.flycatch.authcore.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
@ConfigurationProperties(prefix = "auth")
public class AuthCoreConfig {

    private Jwt jwt;
    private Session session;
    private OAuth2 oauth2;
    private Rbac rbac;
    private RefreshToken refreshToken;
    private Logging logging;
    private Cookies cookies;

    // Getters and setters

    public Jwt getJwt() { return jwt; }
    public void setJwt(Jwt jwt) { this.jwt = jwt; }

    public Session getSession() { return session; }
    public void setSession(Session session) { this.session = session; }

    public OAuth2 getOauth2() { return oauth2; }
    public void setOauth2(OAuth2 oauth2) { this.oauth2 = oauth2; }

    public Rbac getRbac() { return rbac; }
    public void setRbac(Rbac rbac) { this.rbac = rbac; }

    public RefreshToken getRefreshToken() { return refreshToken; }
    public void setRefreshToken(RefreshToken refreshToken) { this.refreshToken = refreshToken; }

    public Logging getLogging() { return logging; }
    public void setLogging(Logging logging) { this.logging = logging; }

    public Cookies getCookies() { return cookies; }
    public void setCookies(Cookies cookies) { this.cookies = cookies; }

    // ================== NESTED CONFIG CLASSES ==================

    public static class Jwt {
        private boolean enabled;
        private String secret;
        private long accessTokenExpiration;
        private long refreshTokenExpiration;

        // Getters and setters
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }

        public String getSecret() { return secret; }
        public void setSecret(String secret) { this.secret = secret; }

        public long getAccessTokenExpiration() { return accessTokenExpiration; }
        public void setAccessTokenExpiration(long accessTokenExpiration) { this.accessTokenExpiration = accessTokenExpiration; }

        public long getRefreshTokenExpiration() { return refreshTokenExpiration; }
        public void setRefreshTokenExpiration(long refreshTokenExpiration) { this.refreshTokenExpiration = refreshTokenExpiration; }
    }

    public static class Session {
        private boolean enabled;
        private String storeType;

        // Getters and setters
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }

        public String getStoreType() { return storeType; }
        public void setStoreType(String storeType) { this.storeType = storeType; }
    }

    public static class OAuth2 {
        private boolean enabled;
        private Client client;

        // Getters and setters
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }

        public Client getClient() { return client; }
        public void setClient(Client client) { this.client = client; }

        public static class Client {
            private Registration registration;
            private Provider provider;

            // Getters and setters
            public Registration getRegistration() { return registration; }
            public void setRegistration(Registration registration) { this.registration = registration; }

            public Provider getProvider() { return provider; }
            public void setProvider(Provider provider) { this.provider = provider; }

            public static class Registration {
                private Google google;

                // Getters and setters
                public Google getGoogle() { return google; }
                public void setGoogle(Google google) { this.google = google; }

                public static class Google {
                    private String clientId;
                    private String clientSecret;
                    private String redirectUri;
                    private List<String> scope;

                    // Getters and setters
                    public String getClientId() { return clientId; }
                    public void setClientId(String clientId) { this.clientId = clientId; }

                    public String getClientSecret() { return clientSecret; }
                    public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }

                    public String getRedirectUri() { return redirectUri; }
                    public void setRedirectUri(String redirectUri) { this.redirectUri = redirectUri; }

                    public List<String> getScope() { return scope; }
                    public void setScope(List<String> scope) { this.scope = scope; }
                }
            }

            public static class Provider {
                private Google google;

                // Getters and setters
                public Google getGoogle() { return google; }
                public void setGoogle(Google google) { this.google = google; }

                public static class Google {
                    private String authorizationUri;
                    private String tokenUri;
                    private String userInfoUri;
                    private String userNameAttribute;

                    // Getters and setters
                    public String getAuthorizationUri() { return authorizationUri; }
                    public void setAuthorizationUri(String authorizationUri) { this.authorizationUri = authorizationUri; }

                    public String getTokenUri() { return tokenUri; }
                    public void setTokenUri(String tokenUri) { this.tokenUri = tokenUri; }

                    public String getUserInfoUri() { return userInfoUri; }
                    public void setUserInfoUri(String userInfoUri) { this.userInfoUri = userInfoUri; }

                    public String getUserNameAttribute() { return userNameAttribute; }
                    public void setUserNameAttribute(String userNameAttribute) { this.userNameAttribute = userNameAttribute; }
                }
            }
        }
    }

    public static class Rbac {
        private boolean enabled;

        // Getters and setters
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
    }

    public static class RefreshToken {
        private boolean enabled;

        // Getters and setters
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
    }

    public static class Logging {
        private boolean enabled;

        // Getters and setters
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
    }

    public static class Cookies {
        private boolean enabled;
        private String name;
        private boolean httpOnly;
        private boolean secure;
        private String sameSite;
        private int maxAge;

        // Getters and setters
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }

        public String getName() { return name; }
        public void setName(String name) { this.name = name; }

        public boolean isHttpOnly() { return httpOnly; }
        public void setHttpOnly(boolean httpOnly) { this.httpOnly = httpOnly; }

        public boolean isSecure() { return secure; }
        public void setSecure(boolean secure) { this.secure = secure; }

        public String getSameSite() { return sameSite; }
        public void setSameSite(String sameSite) { this.sameSite = sameSite; }

        public int getMaxAge() { return maxAge; }
        public void setMaxAge(int maxAge) { this.maxAge = maxAge; }
    }
}
