package com.gw2auth.oauth2.server.service.gw2;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.UUID;

public record Gw2Account(@JsonProperty("id") UUID id, @JsonProperty("name") String name) {
}
