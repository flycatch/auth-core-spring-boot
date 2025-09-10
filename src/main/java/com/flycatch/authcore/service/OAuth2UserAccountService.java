package com.flycatch.authcore.service;

import org.springframework.security.core.Authentication;


    public interface OAuth2UserAccountService {
        void processOAuth2User(Authentication authentication);
    }

