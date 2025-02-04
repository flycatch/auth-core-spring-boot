package com.flycatch.authcore.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "auth")
public class AuthCoreConfig {

    private boolean enableJwt = true;
    private boolean enableSession = true;
    private boolean enableOAuth2 = false;

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
}
