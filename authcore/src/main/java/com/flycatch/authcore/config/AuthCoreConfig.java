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

    public boolean isEnableJwt() {
        return enableJwt;
    }

    public void setEnableJwt(boolean enableJwt) {
        this.enableJwt = enableJwt;
    }

    public boolean isEnableSession() {
        return enableSession;
    }

    public void setEnableSession(boolean enableSession) {
        this.enableSession = enableSession;
    }

    public boolean isEnableOAuth2() {
        return enableOAuth2;
    }

    public void setEnableOAuth2(boolean enableOAuth2) {
        this.enableOAuth2 = enableOAuth2;
    }

    public boolean isEnableRefreshToken() {
        return enableRefreshToken;
    }

    public void setEnableRefreshToken(boolean enableRefreshToken) {
        this.enableRefreshToken = enableRefreshToken;
    }

    public boolean isEnableLogging() {
        return enableLogging;
    }

    public void setEnableLogging(boolean enableLogging) {
        this.enableLogging = enableLogging;
    }
}
