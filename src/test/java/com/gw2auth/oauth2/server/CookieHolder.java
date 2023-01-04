package com.gw2auth.oauth2.server;

import jakarta.servlet.http.Cookie;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultHandler;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.util.*;

public class CookieHolder implements RequestPostProcessor, ResultHandler {

    private final Map<String, Cookie> cookies;

    public CookieHolder() {
        this.cookies = new HashMap<>();
    }

    public void addCookie(Cookie cookie) {
        if (cookie.getMaxAge() > 0) {
            this.cookies.put(cookie.getName(), cookie);
        } else {
            this.cookies.remove(cookie.getName());
        }
    }

    public void removeCookie(String name) {
        this.cookies.remove(name);
    }

    public Cookie getCookie(String name) {
        return this.cookies.get(name);
    }

    @Override
    public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
        final Map<String, Cookie> totalCookies = new HashMap<>();
        final Cookie[] existingCookies = request.getCookies();

        if (existingCookies != null) {
            for (Cookie cookie : existingCookies) {
                if (cookie.getMaxAge() > 0) {
                    totalCookies.putIfAbsent(cookie.getName(), cookie);
                }
            }
        }

        for (Map.Entry<String, Cookie> entry : this.cookies.entrySet()) {
            if (entry.getValue().getMaxAge() > 0) {
                totalCookies.putIfAbsent(entry.getKey(), entry.getValue());
            }
        }

        request.setCookies(totalCookies.values().toArray(new Cookie[0]));

        return request;
    }

    @Override
    public void handle(MvcResult result) {
        for (Cookie cookie : result.getResponse().getCookies()) {
            addCookie(cookie);
        }
    }
}
