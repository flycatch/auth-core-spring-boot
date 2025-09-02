package com.flycatch.authcore;

import com.flycatch.authcore.config.AuthCoreConfig;
import com.flycatch.authcore.rbac.AuthorizationProperties;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;

@AutoConfiguration
@EnableConfigurationProperties({AuthCoreConfig.class, AuthorizationProperties.class})
@ComponentScan(basePackages = "com.flycatch.authcore")
public class AuthCoreAutoConfiguration {
}
