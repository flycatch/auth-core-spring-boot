package com.flycatch.authcore.service;

import com.flycatch.authcore.model.User;
import com.flycatch.authcore.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthCoreUserServiceImpl implements AuthCoreUserService {

    private final UserRepository userRepository;

    public AuthCoreUserServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    @Override
    public User save(String username, String email, String encodedPassword) {
        User user = new User(username, email, encodedPassword);
        return userRepository.save(user);
    }
}
