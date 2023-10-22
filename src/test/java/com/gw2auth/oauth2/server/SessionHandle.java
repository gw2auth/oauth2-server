package com.gw2auth.oauth2.server;

import jakarta.servlet.http.Cookie;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultHandler;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import java.util.*;

public class SessionHandle implements RequestPostProcessor, ResultHandler {

    public static final String DEFAULT_COUNTRY_CODE = "DE";
    public static final String DEFAULT_CITY = "Berlin";
    public static final double DEFAULT_LATITUDE = 52.5162778;
    public static final double DEFAULT_LONGITUDE = 13.3755154;

    private String countryCode;
    private String city;
    private Double latitude;
    private Double longitude;
    private final Map<String, Cookie> cookies;

    public SessionHandle() {
        this(DEFAULT_COUNTRY_CODE, DEFAULT_CITY, DEFAULT_LATITUDE, DEFAULT_LONGITUDE);
    }

    public SessionHandle(String countryCode, String city, Double latitude, Double longitude) {
        this.countryCode = countryCode;
        this.city = city;
        this.latitude = latitude;
        this.longitude = longitude;
        this.cookies = new HashMap<>();
    }

    public void addCookie(Cookie cookie) {
        if (cookie.getMaxAge() != 0) {
            this.cookies.put(cookie.getName(), cookie);
        } else {
            this.cookies.remove(cookie.getName());
        }
    }

    public void removeCookie(String name) {
        this.cookies.remove(name);
    }

    public void setCountryCode(String countryCode) {
        this.countryCode = countryCode;
    }

    public void setCity(String city) {
        this.city = city;
    }

    public void setLatitude(Double latitude) {
        this.latitude = latitude;
    }

    public void setLongitude(Double longitude) {
        this.longitude = longitude;
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
                if (cookie.getMaxAge() != 0) {
                    totalCookies.putIfAbsent(cookie.getName(), cookie);
                }
            }
        }

        for (Map.Entry<String, Cookie> entry : this.cookies.entrySet()) {
            if (entry.getValue().getMaxAge() != 0) {
                totalCookies.putIfAbsent(entry.getKey(), entry.getValue());
            }
        }

        request.setCookies(totalCookies.values().toArray(new Cookie[0]));

        if (this.countryCode != null) {
            request.addHeader("Cloudfront-Viewer-Country", this.countryCode);
        }

        if (this.city != null) {
            request.addHeader("Cloudfront-Viewer-City", this.city);
        }

        if (this.latitude != null) {
            request.addHeader("Cloudfront-Viewer-Latitude", Double.toString(this.latitude));
        }

        if (this.longitude != null) {
            request.addHeader("Cloudfront-Viewer-Longitude", Double.toString(this.longitude));
        }

        return request;
    }

    @Override
    public void handle(MvcResult result) {
        for (Cookie cookie : result.getResponse().getCookies()) {
            addCookie(cookie);
        }
    }
}
