package com.flycatch.authcore.twofactor;

import com.flycatch.authcore.config.AuthCoreConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class EmailSmsOtpService implements OtpService {

    private final Map<String,OtpEntry> otpStorage = new ConcurrentHashMap<>();
    private final AuthCoreConfig cfg;
    @Override
    public void generateAndSendOtp(String username) {
        String otp = String.format("%06d", new SecureRandom().nextInt(1_000_000));

        long expirySeconds;
        if (cfg.getTwoFactor().getMode() == AuthCoreConfig.TwoFactor.Mode.EMAIL) {
            expirySeconds = cfg.getTwoFactor().getEmail().getExpirySeconds();
        } else if (cfg.getTwoFactor().getMode() == AuthCoreConfig.TwoFactor.Mode.SMS) {
            expirySeconds = cfg.getTwoFactor().getSms().getExpirySeconds();
        } else {
            throw new IllegalStateException("TwoFactor mode not configured");
        }

        Instant expiry = Instant.now().plusSeconds(expirySeconds);
        otpStorage.put(username, new OtpEntry(otp, expiry));

        // TODO: send via Email/SMS depending on mode
        System.out.println("Generated OTP for " + username + ": " + otp + " (expires in " + expirySeconds + "s)");
    }


    @Override
    public boolean verifyOtp(String username, String otp) {
        OtpEntry entry = otpStorage.get(username);
        if (entry == null || Instant.now().isAfter(entry.expiry)) {
            otpStorage.remove(username);
            return false;
        }
        boolean valid = entry.otp.equals(otp);
        if (valid) otpStorage.remove(username); // one-time use
        return valid;
    }
    private record OtpEntry(String otp, Instant expiry) {

    }
}
