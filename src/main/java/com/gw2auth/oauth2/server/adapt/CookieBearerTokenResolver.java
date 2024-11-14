package com.gw2auth.oauth2.server.adapt;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;

public class CookieBearerTokenResolver implements BearerTokenResolver {

    private final String cookieName;

    public CookieBearerTokenResolver(String cookieName) {
        this.cookieName = cookieName;
    }

    @Override
    public @Nullable String resolve(HttpServletRequest request) {
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
