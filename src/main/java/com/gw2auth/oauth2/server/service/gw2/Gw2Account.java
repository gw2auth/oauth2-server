package com.gw2auth.oauth2.server.service.gw2;

import com.fasterxml.jackson.annotation.JsonProperty;

public record Gw2Account(@JsonProperty("id") String id, @JsonProperty("name") String name) {
}
