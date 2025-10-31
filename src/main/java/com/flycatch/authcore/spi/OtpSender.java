package com.flycatch.authcore.spi;

public interface OtpSender {
    void sendOtp(String username, String destination, String otpCode);
}
