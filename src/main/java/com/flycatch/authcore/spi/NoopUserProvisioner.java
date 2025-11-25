package com.flycatch.authcore.spi;

/**
 * Default no-op provisioner to keep AuthCore backward-compatible.
 * Host applications can override by providing their own @Component implementing UserProvisioner.
 */
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnMissingBean(UserProvisioner.class)
public class NoopUserProvisioner implements UserProvisioner {

    @Override
    public ProvisionResult provisionIfAbsent(OAuth2UserProfile profile) {
        return ProvisionResult.noop();
    }
}
