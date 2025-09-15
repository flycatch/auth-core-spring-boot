package com.flycatch.authcore.oauth2;

import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;

@RestController
public class OAuth2ProvidersController {

    private final ClientRegistrationRepository registrations;

    public OAuth2ProvidersController(ClientRegistrationRepository registrations) {
        this.registrations = registrations;
    }

    @GetMapping("/auth/oauth2/providers")
    public ResponseEntity<List<Map<String, String>>> listProviders() {
        List<Map<String, String>> out = new ArrayList<>();
        forEachRegistration(reg -> {
            Map<String, String> e = new LinkedHashMap<>();
            e.put("registrationId", reg.getRegistrationId());
            // Standard Spring entry point: /oauth2/authorization/{registrationId}
            e.put("authorizationUrl", "/oauth2/authorization/" + reg.getRegistrationId());
            e.put("clientName", reg.getClientName());
            out.add(e);
        });
        return ResponseEntity.ok(out);
    }

    private void forEachRegistration(java.util.function.Consumer<ClientRegistration> consumer) {
        // ClientRegistrationRepository is usually an InMemory repo (iterable)
        if (registrations instanceof Iterable<?> it) {
            for (Object o : it) {
                if (o instanceof ClientRegistration reg) consumer.accept(reg);
            }
        }
    }
}
