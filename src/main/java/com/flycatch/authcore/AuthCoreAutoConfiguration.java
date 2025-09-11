package com.flycatch.authcore;

import com.flycatch.authcore.config.AuthCoreConfig;
import com.flycatch.authcore.rbac.AuthorizationProperties;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.web.client.RestTemplate;

@AutoConfiguration
@EnableConfigurationProperties({AuthCoreConfig.class, AuthorizationProperties.class})
@ComponentScan(basePackages = "com.flycatch.authcore")
public class AuthCoreAutoConfiguration {
    @Bean
    @ConditionalOnMissingBean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}
