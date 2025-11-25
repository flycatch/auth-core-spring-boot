package com.flycatch.authcore.config;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Setter
@Getter
@ConfigurationProperties(prefix = "auth")
public class AuthCoreConfig {

    private Jwt jwt = new Jwt();
    private Session session = new Session();
    private Logging logging = new Logging();
    private Cookies cookies = new Cookies();

    private RefreshToken refreshToken = new RefreshToken();
    private Endpoints endpoints = new Endpoints();

    /** OAuth2 login controls (enable + redirects + JWT emission) */
    private OAuth2 oauth2 = new OAuth2();
    private TwoFactor twoFactor = new TwoFactor();


    @Setter
    @Getter
    public static class Jwt {
        private boolean enabled = true;
        private String secret;
        /** Expirations in milliseconds */
        private long accessTokenExpiration = 900_000;          // 15m
        private long refreshTokenExpiration = 2_592_000_000L;  // 30d
        private boolean refreshTokenEnabled = false;
    }

    @Setter
    @Getter
    public static class Session {
        private boolean enabled = false;
        private String storeType = "jdbc"; // jdbc | redis | none
    }

    @Setter
    @Getter
    public static class Logging {
        private boolean enabled = false;
    }

    @Setter
    @Getter
    public static class Cookies {
        private boolean enabled = false;
        private String name = "AuthRefreshToken";
        private boolean httpOnly = true;
        private boolean secure = false;
        private String sameSite = "Strict"; // Strict | Lax | None
        private int maxAge = 604800; // seconds (7 days)
    }

    @Setter
    @Getter
    public static class RefreshToken {
        private boolean enabled = false;
    }

    @Setter
    @Getter
    public static class Endpoints {
        private boolean loginEnabled = false;
        private boolean refreshEnabled = false;
        private boolean logoutEnabled = false;
    }

    @Setter
    @Getter
    public static class OAuth2 {
        private boolean enabled = false;
        private String successRedirect = "/";
        private String failureRedirect = "/login?error=oauth2";
        private String accessTokenParam = "accessToken";
        private String refreshTokenParam = "refreshToken";
        private boolean issueJwt = true;
        private boolean includeAuthorities = true;
        private boolean setRefreshCookie = true;
        private boolean appendTokensInRedirect = false;

        /** enable calling a host-provided UserProvisioner on OAuth2 success */
        private boolean autoProvisionEnabled = true;

        /** fallback role if no authorities are returned from provider/provisioner */
        private String defaultRole = "ROLE_USER";

        /** === Authorization-code style flow (no tokens to browser) === */

        /**
         * If true:
         *  - OAuth2 success handler issues a short-lived "code"
         *  - Browser is redirected to successRedirect?code=XYZ&provider=google
         *  - No access/refresh tokens are sent to the browser
         *  - Client backend must call /auth/oauth2/exchange to swap code → tokens
         */
        private boolean authorizationCodeEnabled = false;

        /** Query-parameter name used when redirecting back to frontend */
        private String codeParam = "code";

        /** Generated authorization-code length (min 16, default 40) */
        private int codeLength = 40;

        /** Code TTL (seconds) before it expires and becomes invalid */
        private long codeTtlSeconds = 300L; // 5 minutes
    }

    @Setter
    @Getter
    public static class TwoFactor {
        private boolean enabled = false;
        private String type = "email"; // email or sms (future use)
        private int length = 6;        // digits/characters
        private boolean alphanumeric = false;
        private long expirySeconds = 300; // OTP validity (5 min)
    }

    @PostConstruct
    public void syncLegacyRefresh() {
        if (this.refreshToken != null && this.refreshToken.isEnabled() && !this.jwt.isRefreshTokenEnabled()) {
            this.jwt.setRefreshTokenEnabled(true);
        }
    }
}
