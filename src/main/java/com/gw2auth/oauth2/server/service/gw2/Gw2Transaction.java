package com.gw2auth.oauth2.server.service.gw2;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

public record Gw2Transaction(@JsonProperty("item_id") long itemId, @JsonProperty("quantity") int quantity, @JsonProperty("price") long price, @JsonProperty("created") Instant created) {
}
