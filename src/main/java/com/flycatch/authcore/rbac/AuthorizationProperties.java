package com.flycatch.authcore.rbac;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Getter
@Setter
@ConfigurationProperties(prefix = "authorization")
public class AuthorizationProperties {
    private Map<String, String> permissions = new LinkedHashMap<>();
    private Map<String, List<String>> roles = new LinkedHashMap<>();
}
