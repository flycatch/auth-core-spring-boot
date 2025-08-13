package com.flycatch.authcore;

import com.flycatch.authcore.config.AuthCoreConfig;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;

/**
 * Auto-config so the library binds properties and exposes components when added as a dependency.
 */
@AutoConfiguration
@EnableConfigurationProperties(AuthCoreConfig.class)
@ComponentScan(basePackages = "com.flycatch.authcore")
public class AuthCoreAutoConfiguration {
}
