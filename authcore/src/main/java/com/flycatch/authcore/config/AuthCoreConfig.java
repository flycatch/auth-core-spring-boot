package com.flycatch.authcore.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "auth")
public class AuthCoreConfig {

    private boolean enableJwt;
    private boolean enableSession;
    private boolean enableOAuth2;
    private boolean enableRefreshToken;
    private boolean enableLogging;
    private boolean enableRbac = true;

    // Cookie settings
    private boolean enableCookies;
    private String cookieName;
    private boolean cookieHttpOnly;
    private boolean cookieSecure;
    private String cookieSameSite;
    private int cookieMaxAge;

    public boolean isEnableJwt() { return enableJwt; }
    public void setEnableJwt(boolean enableJwt) { this.enableJwt = enableJwt; }

    public boolean isEnableSession() { return enableSession; }
    public void setEnableSession(boolean enableSession) { this.enableSession = enableSession; }

    public boolean isEnableOAuth2() { return enableOAuth2; }
    public void setEnableOAuth2(boolean enableOAuth2) { this.enableOAuth2 = enableOAuth2; }

    public boolean isEnableRefreshToken() { return enableRefreshToken; }
    public void setEnableRefreshToken(boolean enableRefreshToken) { this.enableRefreshToken = enableRefreshToken; }

    public boolean isEnableLogging() { return enableLogging; }
    public void setEnableLogging(boolean enableLogging) { this.enableLogging = enableLogging; }

    public boolean isEnableCookies() { return enableCookies; }
    public void setEnableCookies(boolean enableCookies) { this.enableCookies = enableCookies; }

    public String getCookieName() { return cookieName; }
    public void setCookieName(String cookieName) { this.cookieName = cookieName; }

    public boolean isCookieHttpOnly() { return cookieHttpOnly; }
    public void setCookieHttpOnly(boolean cookieHttpOnly) { this.cookieHttpOnly = cookieHttpOnly; }

    public boolean isCookieSecure() { return cookieSecure; }
    public void setCookieSecure(boolean cookieSecure) { this.cookieSecure = cookieSecure; }

    public String getCookieSameSite() { return cookieSameSite; }
    public void setCookieSameSite(String cookieSameSite) { this.cookieSameSite = cookieSameSite; }

    public int getCookieMaxAge() { return cookieMaxAge; }
    public void setCookieMaxAge(int cookieMaxAge) { this.cookieMaxAge = cookieMaxAge; }

    public boolean isEnableRbac() { return enableRbac; }
    public void setEnableRbac(boolean enableRbac) { this.enableRbac = enableRbac; }
}
