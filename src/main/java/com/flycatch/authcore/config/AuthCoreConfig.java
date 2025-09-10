package com.flycatch.authcore.config;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Pure properties holder. Client app controls everything via application.yml.
 */
@Setter
@Getter
@ConfigurationProperties(prefix = "auth")
public class AuthCoreConfig {

    private Jwt jwt = new Jwt();
    private Session session = new Session();
    private Logging logging = new Logging();
    private Cookies cookies = new Cookies();
    private Oauth2 oauth2 = new Oauth2();

    /** Legacy support: auth.refresh-token.enabled */
    private RefreshToken refreshToken = new RefreshToken();

    /** Endpoint toggles for white-label controllers */
    private Endpoints endpoints = new Endpoints();

    @Setter @Getter
    public static class Jwt {
        private boolean enabled = true;
        private String secret;
        /** Expirations in milliseconds to match YAML usage */
        private long accessTokenExpiration = 900_000;          // 15m
        private long refreshTokenExpiration = 2_592_000_000L;  // 30d
        private boolean refreshTokenEnabled = false;
    }

    @Setter @Getter
    public static class Session {
        private boolean enabled = false;
        private String storeType = "jdbc"; // jdbc | redis | none
    }

    @Setter @Getter
    public static class Logging {
        private boolean enabled = false;
    }

    @Setter @Getter
    public static class Cookies {
        private boolean enabled = false;
        private String name = "AuthRefreshToken";
        private boolean httpOnly = true;
        private boolean secure = false;
        private String sameSite = "Strict"; // Strict | Lax | None
        private int maxAge = 604800; // seconds (7 days)
    }

    @Setter @Getter
    public static class RefreshToken {
        /** Legacy flag location (back-compat) */
        private boolean enabled = false;
    }

    @Setter @Getter
    public static class Endpoints {
        private boolean loginEnabled = false;
        private boolean refreshEnabled = false;
        private boolean logoutEnabled = false;
    }
    @Setter@Getter
    public static class Oauth2 {
        private boolean enabled = false;
        private Map<String,Provider> providers = new HashMap<>();}

        @Setter @Getter
        public static class Provider {
            private String clientId;
            private String clientSecret;
            private String redirectUri;
            private List<String> scopes = List.of("openid", "profile", "email");
            private String authUri;
            private String tokenUri;
            private String userInfoUri;
            private String authorizationUri;
            private String userNameAttribute;
        }
        // Future expansion

    /** Sync legacy refresh toggle with modern flag */
    @PostConstruct
    public void syncLegacyRefresh() {
        if (this.refreshToken != null && this.refreshToken.isEnabled() && !this.jwt.isRefreshTokenEnabled()) {
            this.jwt.setRefreshTokenEnabled(true);
        }
    }
}
