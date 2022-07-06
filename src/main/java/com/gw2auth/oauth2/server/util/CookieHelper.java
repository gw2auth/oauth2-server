package com.gw2auth.oauth2.server.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.time.Instant;

public final class CookieHelper {

    public static void addCookie(HttpServletRequest request, HttpServletResponse response, String name, String value, Instant expiresAt) {
        final Cookie cookie = new Cookie(name, value);
        cookie.setMaxAge((int) Duration.between(Instant.now(), expiresAt).getSeconds());
        cookie.setPath(getRequestContext(request));
        cookie.setSecure(request.isSecure());
        cookie.setHttpOnly(true);

        response.addCookie(cookie);
    }

    public static void clearCookie(HttpServletRequest request, HttpServletResponse response, String name) {
        final Cookie cookie = new Cookie(name, null);
        cookie.setMaxAge(0);
        cookie.setPath(getRequestContext(request));
        cookie.setSecure(request.isSecure());
        cookie.setHttpOnly(true);

        response.addCookie(cookie);
    }

    private static String getRequestContext(HttpServletRequest request) {
        String contextPath = request.getContextPath();
        return (contextPath.length() > 0) ? contextPath : "/";
    }
}
