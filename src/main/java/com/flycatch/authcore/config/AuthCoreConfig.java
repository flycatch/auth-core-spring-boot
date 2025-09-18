package com.flycatch.authcore.config;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

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
    private TwoFactor twoFactor = new TwoFactor();

    /** Legacy support: auth.refresh-token.enabled */
    private RefreshToken refreshToken = new RefreshToken();

    /** Endpoint toggles for white-label controllers */
    private Endpoints endpoints = new Endpoints();

    /** OAuth2 login controls (enable + redirects + JWT emission) */
    private OAuth2 oauth2 = new OAuth2();

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

    @Setter @Getter
    public static class OAuth2 {
        /** Turn on oauth2Login() flow */
        private boolean enabled = false;

        /** Where to redirect browser after successful OAuth2 login */
        private String successRedirect = "/";

        /** Where to redirect on failure */
        private String failureRedirect = "/login?error=oauth2";

        /** Append tokens as query params on the success redirect */
        private String accessTokenParam = "accessToken";
        private String refreshTokenParam = "refreshToken";

        /** Emit JWT access token after OAuth2 login */
        private boolean issueJwt = true;

        /** Include expanded authorities in JWT claim (same as username/password) */
        private boolean includeAuthorities = true;

        /** If true and cookies.enabled=true, refresh token is also set as cookie */
        private boolean setRefreshCookie = true;
    }

    @Setter @Getter
    public static class TwoFactor {
        private boolean enabled = false; // Global switch
        private Mode mode = Mode.NONE;   // EMAIL or SMS

        private EmailProperties email = new EmailProperties();
        private SmsProperties sms = new SmsProperties();

        public enum Mode { NONE, EMAIL, SMS }


        @Getter @Setter
        public static class EmailProperties {
            private String from;     // e.g. "no-reply@company.com"
            private String subject;  // e.g. "Your OTP Code"
            private long expirySeconds = 300; // default 5 min

        }
        @Getter @Setter
        public static class SmsProperties {
            private String provider; // e.g. "twilio"
            private String apiKey;
            private String senderId;
            private long expirySeconds = 300;

        }
    }


    /** Sync legacy refresh toggle with modern flag */
    @PostConstruct
    public void syncLegacyRefresh() {
        if (this.refreshToken != null && this.refreshToken.isEnabled() && !this.jwt.isRefreshTokenEnabled()) {
            this.jwt.setRefreshTokenEnabled(true);
        }
    }
}
