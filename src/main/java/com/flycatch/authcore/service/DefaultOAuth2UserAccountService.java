package com.flycatch.authcore.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
    @Slf4j
    @Service
    public class DefaultOAuth2UserAccountService implements OAuth2UserAccountService {

        @Override
        public void processOAuth2User(Authentication authentication) {
            log.info(" Default user processing for {}", authentication.getName());
            // In real usage: create user account, assign roles, etc.
        }
    }

