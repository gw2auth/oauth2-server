package com.gw2auth.oauth2.server.util;

import org.springframework.security.web.savedrequest.CookieRequestCache;

import java.lang.reflect.Field;

public final class Constants {

    public static final String LOGOUT_URL = "/auth/logout";
    public static final String ACCESS_TOKEN_COOKIE_NAME = "BEARER";
    public static final String REDIRECT_URI_COOKIE_NAME;

    static {
        try {
            final Field field = CookieRequestCache.class.getDeclaredField("COOKIE_NAME");
            final boolean wasAccessible = field.canAccess(null);
            field.setAccessible(true);
            REDIRECT_URI_COOKIE_NAME = (String) field.get(null);
            field.setAccessible(wasAccessible);
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException(e);
        }
    }
}
