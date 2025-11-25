package com.flycatch.authcore.config;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Setter
@Getter
@ConfigurationProperties(prefix = "auth")
public class AuthCoreConfig {

    private static final Logger log = LoggerFactory.getLogger(AuthCoreConfig.class);

    private Jwt jwt = new Jwt();
    private Session session = new Session();
    private Logging logging = new Logging();
    private Cookies cookies = new Cookies();

    private RefreshToken refreshToken = new RefreshToken();
    private Endpoints endpoints = new Endpoints();

    private OAuth2 oauth2 = new OAuth2();
    private TwoFactor twoFactor = new TwoFactor();

    @Setter
    @Getter
    public static class Jwt {
        private boolean enabled = true;
        private String secret;
        private long accessTokenExpiration = 900_000;
        private long refreshTokenExpiration = 2_592_000_000L;
        private boolean refreshTokenEnabled = false;
    }

    @Setter
    @Getter
    public static class Session {
        private boolean enabled = false;
        private String storeType = "jdbc";
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
        private String sameSite = "Strict";
        private int maxAge = 604800;
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

        private boolean autoProvisionEnabled = true;
        private String defaultRole = "ROLE_USER";

        private boolean authorizationCodeEnabled = false;
        private String codeParam = "code";
        private int codeLength = 40;
        private long codeTtlSeconds = 300L;
    }

    @Setter
    @Getter
    public static class TwoFactor {
        private boolean enabled = false;
        private String type = "email";
        private int length = 6;
        private boolean alphanumeric = false;
        private long expirySeconds = 300;
    }

    @PostConstruct
    public void syncLegacyRefreshAndValidate() {
        if (this.refreshToken != null && this.refreshToken.isEnabled() && !this.jwt.isRefreshTokenEnabled()) {
            this.jwt.setRefreshTokenEnabled(true);
            if (logging != null && logging.isEnabled()) {
                log.info("AuthCore: syncLegacyRefresh enabled JWT refresh tokens because auth.refresh-token.enabled=true");
            }
        }

        validateJwt();
        validateCookies();
        validateOAuth2();
        validateTwoFactor();
        validateModesSummary();
    }

    private void validateJwt() {
        if (jwt != null && jwt.isEnabled()) {
            if (jwt.getSecret() == null || jwt.getSecret().isBlank()) {
                log.error("AuthCore config error: auth.jwt.enabled=true but auth.jwt.secret is not configured.");
            }
            if (jwt.isRefreshTokenEnabled()
                    && jwt.getRefreshTokenExpiration() > 0
                    && jwt.getAccessTokenExpiration() > 0
                    && jwt.getRefreshTokenExpiration() <= jwt.getAccessTokenExpiration()) {
                throw new IllegalStateException(
                        "Invalid AuthCore configuration: refresh token expiration must be greater than access token expiration."
                );
            }
        }
    }

    private void validateCookies() {
        if (cookies != null && cookies.isEnabled()) {
            if (cookies.getName() == null || cookies.getName().isBlank()) {
                throw new IllegalStateException(
                        "Invalid AuthCore configuration: auth.cookies.enabled=true but auth.cookies.name is empty."
                );
            }
            if ("None".equalsIgnoreCase(cookies.getSameSite()) && !cookies.isSecure()) {
                log.warn("AuthCore warning: Cookies with SameSite=None and secure=false may be rejected by modern browsers.");
            }
        }
    }

    private void validateOAuth2() {
        if (oauth2 == null) {
            return;
        }

        if (oauth2.isAuthorizationCodeEnabled()) {
            if (!oauth2.isEnabled()) {
                throw new IllegalStateException(
                        "Invalid AuthCore configuration: authorization-code flow requires auth.oauth2.enabled=true."
                );
            }
            if (jwt == null || !jwt.isEnabled()) {
                throw new IllegalStateException(
                        "Invalid AuthCore configuration: auth.oauth2.authorization-code-enabled=true requires auth.jwt.enabled=true. " +
                                "Enable JWT or disable authorization-code flow."
                );
            }
            if (oauth2.getCodeLength() < 16) {
                throw new IllegalStateException(
                        "Invalid AuthCore configuration: auth.oauth2.code-length must be >= 16 for security reasons."
                );
            }
            if (oauth2.getCodeTtlSeconds() < 30L) {
                throw new IllegalStateException(
                        "Invalid AuthCore configuration: auth.oauth2.code-ttl-seconds must be at least 30 seconds."
                );
            }
            if (oauth2.getSuccessRedirect() == null || oauth2.getSuccessRedirect().isBlank()) {
                throw new IllegalStateException(
                        "Invalid AuthCore configuration: OAuth2 successRedirect must not be empty when authorization-code flow is enabled."
                );
            }
        }

        if (oauth2.isEnabled()) {
            if (oauth2.getSuccessRedirect() == null || oauth2.getSuccessRedirect().isBlank()) {
                log.warn("AuthCore warning: OAuth2 is enabled but successRedirect is blank.");
            }
            if (oauth2.getFailureRedirect() == null || oauth2.getFailureRedirect().isBlank()) {
                log.warn("AuthCore warning: OAuth2 is enabled but failureRedirect is blank.");
            }
            if (oauth2.isAppendTokensInRedirect() && oauth2.isAuthorizationCodeEnabled()) {
                log.warn("AuthCore warning: appendTokensInRedirect=true is ignored because authorization-code-enabled=true.");
            }
        }
    }

    private void validateTwoFactor() {
        if (twoFactor != null && twoFactor.isEnabled()) {
            if (twoFactor.getLength() < 4) {
                throw new IllegalStateException(
                        "Invalid AuthCore configuration: OTP length must be >= 4."
                );
            }
            if (twoFactor.getExpirySeconds() < 30L) {
                throw new IllegalStateException(
                        "Invalid AuthCore configuration: OTP expiry must be at least 30 seconds."
                );
            }
        }
    }

    private void validateModesSummary() {
        if (logging != null && logging.isEnabled()) {
            boolean jwtEnabled = jwt != null && jwt.isEnabled();
            boolean sessionEnabled = session != null && session.isEnabled();
            boolean oauthEnabled = oauth2 != null && oauth2.isEnabled();
            boolean codeFlow = oauth2 != null && oauth2.isAuthorizationCodeEnabled();

            if (jwtEnabled && sessionEnabled) {
                log.warn("AuthCore warning: Both JWT and Session authentication are enabled. " +
                        "JWT will be used for stateless flows, Session for requests with HttpServletRequest.");
            }

            log.info("AuthCore config: JWT enabled={}, Session enabled={}, OAuth2 enabled={}, OAuth2 code-flow={}",
                    jwtEnabled, sessionEnabled, oauthEnabled, codeFlow);
        }
    }
}
