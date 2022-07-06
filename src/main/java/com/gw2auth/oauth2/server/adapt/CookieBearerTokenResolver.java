package com.gw2auth.oauth2.server.adapt;

import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

public class CookieBearerTokenResolver implements BearerTokenResolver {

    private final String cookieName;

    public CookieBearerTokenResolver(String cookieName) {
        this.cookieName = cookieName;
    }

    @Override
    public String resolve(HttpServletRequest request) {
        final Cookie[] cookies = request.getCookies();
        String value = null;

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(this.cookieName)) {
                    value = cookie.getValue();
                    if (value.isEmpty()) {
                        value = null;
                    }
                    break;
                }
            }
        }

        return value;
    }
}
