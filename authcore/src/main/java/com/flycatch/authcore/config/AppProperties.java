package com.alphastarav.hrms.config;

import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.ArrayList;

/**
 * This class in keeps the configuration data of prefix app in
 * application.yml
 */
@Getter
@Validated
@ConfigurationProperties(prefix = "app")
@RequiredArgsConstructor
public class AppProperties {
    private final Utils utils;
    private final JwtConfig jwt;
    private final Cors cors;

    /**
     * The configuration class for jwt.
     *
     * @param secret    the fixed secret to use.
     * @param algorithm the signature algorithm to use
     */
    public record JwtConfig(
            @NotNull
            String secret,
            @NotNull
            SignatureAlgorithm algorithm
    ) {
    }

    /**
     * configuration values for cors.
     *
     * @param allowedOrigins allowedOrigins
     * @param allowedMethods allowedMethods
     * @param allowedHeaders allowedHeaders
     * @param exposedHeaders exposedHeaders
     * @param credentials    credentials
     */
    public record Cors(
            @NotEmpty
            ArrayList<String> allowedOrigins,
            @NotEmpty
            ArrayList<String> allowedMethods,
            @NotEmpty
            ArrayList<String> allowedHeaders,
            @NotNull
            ArrayList<String> exposedHeaders,
            boolean credentials
    ) {
    }

    /**
     * Contains utility parameters.
     *
     * @param uploadFolder         folder to which files are uploaded to.
     * @param timeZone             The timezone in which the application should run at.
     */

    public record Utils(
            @NotNull
            String uploadFolder,
            @NotNull
            String timeZone
    ) {
    }
}
