package com.gw2auth.oauth2.server.service.security;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public record SessionMetadata(@JsonProperty("lat") double latitude, @JsonProperty("lng") double longitude) {

    public static final SessionMetadata FALLBACK = new SessionMetadata(0.0, 0.0);
}
