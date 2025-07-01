package com.alphastarav.hrms.component;


import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.stereotype.Component;

import java.util.Locale;

/**
 * Messages component.
 */
@Component
@RequiredArgsConstructor()
public class Message {

    private final MessageSource delegate;


    public String getMessage(String key, Object... args) {
        return getMessage(key, null, args);
    }

    public String getMessage(String key, Locale locale, Object... args) {
        return delegate.getMessage(key, args, getLocale(locale));
    }

    public String getMessage(String key, String defaultMessage, Locale locale, Object... args) {
        return delegate.getMessage(key, args, defaultMessage, getLocale(locale));
    }

    private Locale getLocale(Locale locale) {
        return locale == null ? LocaleContextHolder.getLocale() : locale;
    }
}
