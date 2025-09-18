package com.flycatch.authcore.twofactor;

public interface OtpService {
    void generateAndSendOtp(String username);
    boolean verifyOtp(String username, String otp);
}
