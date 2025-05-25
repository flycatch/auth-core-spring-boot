package com.flycatch.authcore.service;

import com.flycatch.authcore.model.AuthCoreUser;

import java.util.Optional;

public interface AuthCoreUserService {
    Optional<? extends AuthCoreUser> findByUsername(String username);
    AuthCoreUser save(String username, String encodedPassword);
}
