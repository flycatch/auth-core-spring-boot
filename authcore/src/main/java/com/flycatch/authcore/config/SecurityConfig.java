package com.flycatch.authcore.config;

import com.flycatch.authcore.middleware.JwtAuthFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final AuthCoreConfig authCoreConfig;
    public SecurityConfig(JwtAuthFilter jwtAuthFilter, AuthCoreConfig authCoreConfig) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.authCoreConfig = authCoreConfig;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable) //
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/**").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                .defaultSuccessUrl("/auth", true)  // Redirect after login success
        )
                .sessionManagement(session -> session
                        .maximumSessions(1)
                )
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        if (authCoreConfig.isEnableSession()) {
            http.sessionManagement(session -> session
                    .maximumSessions(1)
            );
        } else {
            http.sessionManagement(session -> session
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            );
        }

        // Conditional JWT filter
        if (authCoreConfig.isEnableJwt()) {
            http.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        }

        // Conditional OAuth2 login
        if (authCoreConfig.isEnableOAuth2()) {
            http.oauth2Login(oauth2 -> oauth2
                    .defaultSuccessUrl("/oauth2/success", true)
            );
        }

        return http.build();
    }



    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }
}
