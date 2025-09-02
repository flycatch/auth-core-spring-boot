package com.flycatch.authcore.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

/**
 * Enables @PreAuthorize/@PostAuthorize/@Secured/@RolesAllowed and
 * wires RoleHierarchy + PermissionEvaluator into the expression handler.
 */
@Configuration
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class MethodSecurityConfig {

    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl rh = new RoleHierarchyImpl();
        rh.setHierarchy(""); // no implicit inheritance
        return rh;
    }

    @Bean
    public PermissionEvaluator permissionEvaluator() {
        return new SimplePermissionEvaluator();
    }

    /**
     * IMPORTANT: expose bean named methodSecurityExpressionHandler so Spring uses it.
     */
    @Bean
    public MethodSecurityExpressionHandler methodSecurityExpressionHandler(
            RoleHierarchy roleHierarchy,
            PermissionEvaluator permissionEvaluator
    ) {
        DefaultMethodSecurityExpressionHandler h = new DefaultMethodSecurityExpressionHandler();
        h.setRoleHierarchy(roleHierarchy);
        h.setPermissionEvaluator(permissionEvaluator);
        return h;
    }
}
