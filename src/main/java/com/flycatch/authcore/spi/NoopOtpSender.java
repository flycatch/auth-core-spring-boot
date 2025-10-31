package com.flycatch.authcore.spi;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class NoopOtpSender implements OtpSender {
    private static final Logger log = LoggerFactory.getLogger(NoopOtpSender.class);

    @Override
    public void sendOtp(String username, String destination, String otpCode) {
        log.info("[NoopOtpSender] OTP for {} -> {} : {}", username, destination, otpCode);
    }
}
