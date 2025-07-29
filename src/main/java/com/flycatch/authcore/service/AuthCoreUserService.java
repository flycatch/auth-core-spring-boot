package com.flycatch.authcore.service;

import java.util.Optional;

public interface AuthCoreUserService {
    Optional<Object> findByUsername(String username);
    Optional<Object> findByEmail(String email);
    Object save(String username, String email, String encodedPassword);
}