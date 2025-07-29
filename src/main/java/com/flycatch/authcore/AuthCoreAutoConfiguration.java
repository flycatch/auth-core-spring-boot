package com.flycatch.authcore;

import com.flycatch.authcore.config.AuthCoreConfig;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;

@AutoConfiguration
@ComponentScan(basePackages = "com.flycatch.authcore")
public class AuthCoreAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public AuthCoreConfig authCoreConfig() {
        return new AuthCoreConfig();
    }
}
