package com.flycatch.authcore.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Setter
@Getter
@Configuration
@ConfigurationProperties(prefix = "auth")
public class AuthCoreConfig {
    private Jwt jwt;
    private Session session;
    private RefreshToken refreshToken;
    private Logging logging;
    private Cookies cookies;

    @Setter
    @Getter
    public static class Jwt {
        private boolean enabled;
        private String secret;
        private long accessTokenExpiration;
        private long refreshTokenExpiration;

    }

    @Setter
    @Getter
    public static class Session {
        private boolean enabled;
        private String storeType;

    }

    @Setter
    @Getter
    public static class RefreshToken {
        private boolean enabled;

    }

    @Setter
    @Getter
    public static class Logging {
        private boolean enabled;

    }

    @Setter
    @Getter
    public static class Cookies {
        private boolean enabled;
        private String name;
        private boolean httpOnly;
        private boolean secure;
        private String sameSite;
        private int maxAge;

    }
}