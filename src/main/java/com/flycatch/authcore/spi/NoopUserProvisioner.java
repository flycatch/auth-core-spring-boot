package com.flycatch.authcore.spi;

import org.springframework.stereotype.Component;

/**
 * Default no-op provisioner to keep AuthCore backward-compatible.
 * Host applications can override by providing their own @Component implementing UserProvisioner.
 */
@Component
public class NoopUserProvisioner implements UserProvisioner {
    @Override
    public ProvisionResult provisionIfAbsent(OAuth2UserProfile profile) {
        return ProvisionResult.noop();
    }
}
