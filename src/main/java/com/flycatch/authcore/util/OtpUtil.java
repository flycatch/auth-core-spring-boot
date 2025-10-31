package com.flycatch.authcore.util;

import com.flycatch.authcore.config.AuthCoreConfig;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class OtpUtil {
    private final AuthCoreConfig cfg;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, OtpEntry> otpStore = new ConcurrentHashMap<>();

    public OtpUtil(AuthCoreConfig cfg) { this.cfg = cfg; }

    public String generate(String username) {
        AuthCoreConfig.TwoFactor t = cfg.getTwoFactor();
        String chars = t.isAlphanumeric() ? "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" : "0123456789";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < t.getLength(); i++) sb.append(chars.charAt(random.nextInt(chars.length())));
        String code = sb.toString();
        otpStore.put(username, new OtpEntry(code, Instant.now().plusSeconds(t.getExpirySeconds())));
        return code;
    }

    public boolean verify(String username, String code) {
        OtpEntry entry = otpStore.get(username);
        if (entry == null) return false;
        if (Instant.now().isAfter(entry.expiresAt)) {
            otpStore.remove(username);
            return false;
        }
        boolean match = entry.code.equals(code);
        if (match) otpStore.remove(username);
        return match;
    }

    private record OtpEntry(String code, Instant expiresAt) {}
}
