package com.gw2auth.oauth2.server.web;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

public record AuthInfoResponse(@JsonProperty("sessionId") String sessionId,
                               @JsonProperty("sessionCreationTime") Instant sessionCreationTime,
                               @JsonProperty("issuer") String issuer) {
}
