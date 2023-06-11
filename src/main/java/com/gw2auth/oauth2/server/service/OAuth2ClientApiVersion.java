package com.gw2auth.oauth2.server.service;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum OAuth2ClientApiVersion {

    V0(0),
    V1(1);

    public static final OAuth2ClientApiVersion CURRENT = V0;

    private final int value;
    
    OAuth2ClientApiVersion(int value) {
        this.value = value;
    }

    @JsonValue
    public int value() {
        return this.value;
    }
    
    @JsonCreator
    public static OAuth2ClientApiVersion fromValueRequired(int version) {
        return switch (version) {
            case 0 -> V0;
            case 1 -> V1;
            default -> throw new IllegalArgumentException("Unknown API version: " + version);
        };
    }
}
