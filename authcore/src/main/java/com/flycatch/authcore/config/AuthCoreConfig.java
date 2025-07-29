package com.flycatch.authcore.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "auth")
public class AuthCoreConfig {
    private Jwt jwt;
    private Session session;
    private RefreshToken refreshToken;
    private Logging logging;
    private Cookies cookies;

    public Jwt getJwt() { return jwt; }
    public void setJwt(Jwt jwt) { this.jwt = jwt; }

    public Session getSession() { return session; }
    public void setSession(Session session) { this.session = session; }

    public RefreshToken getRefreshToken() { return refreshToken; }
    public void setRefreshToken(RefreshToken refreshToken) { this.refreshToken = refreshToken; }

    public Logging getLogging() { return logging; }
    public void setLogging(Logging logging) { this.logging = logging; }

    public Cookies getCookies() { return cookies; }
    public void setCookies(Cookies cookies) { this.cookies = cookies; }

    public static class Jwt {
        private boolean enabled;
        private String secret;
        private long accessTokenExpiration;
        private long refreshTokenExpiration;

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

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }

        public String getStoreType() { return storeType; }
        public void setStoreType(String storeType) { this.storeType = storeType; }
    }

    public static class RefreshToken {
        private boolean enabled;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
    }

    public static class Logging {
        private boolean enabled;

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