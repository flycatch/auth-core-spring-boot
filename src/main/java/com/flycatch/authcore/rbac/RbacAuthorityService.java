package com.flycatch.authcore.rbac;

import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Expand ROLE_* authorities into permission authorities from client's YAML (authorization.roles).
 * Also keeps any pre-existing permission authorities.
 * Adds PERM_ mirror for compatibility with hasAuthority('PERM_X').
 */
@Component
public class RbacAuthorityService {

    private final AuthorizationProperties props;

    public RbacAuthorityService(AuthorizationProperties props) {
        this.props = props;
    }

    public Set<String> expandAuthorities(Collection<String> baseAuthorities) {
        if (baseAuthorities == null || baseAuthorities.isEmpty()) return Collections.emptySet();

        Set<String> out = new LinkedHashSet<>(
                baseAuthorities.stream()
                        .filter(Objects::nonNull)
                        .map(String::trim)
                        .filter(s -> !s.isEmpty())
                        .collect(Collectors.toList())
        );

        // find ROLE_* and expand via YAML
        Set<String> roleNames = out.stream()
                .filter(a -> a.startsWith("ROLE_"))
                .map(a -> a.substring("ROLE_".length()))
                .collect(Collectors.toCollection(LinkedHashSet::new));

        for (String role : roleNames) {
            List<String> perms = props.getRoles().getOrDefault(role, Collections.emptyList());
            for (String p : perms) {
                if (p == null) continue;
                String perm = p.trim();
                if (perm.isEmpty()) continue;

                out.add(perm); // plain permission (used by @PreAuthorize("hasAuthority('READ_CHAT_ROOMS')"))
                if (!perm.startsWith("PERM_")) {
                    out.add("PERM_" + perm); // mirror
                }
            }
        }

        return out;
    }
}
