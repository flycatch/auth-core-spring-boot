package com.flycatch.authcore.model;

import java.util.Set;

public interface AuthCoreUser {
    String getUsername();
    String getPassword();
    Set<String> getRoles();
}
