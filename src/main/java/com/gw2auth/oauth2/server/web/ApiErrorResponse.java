package com.gw2auth.oauth2.server.web;

import com.fasterxml.jackson.annotation.JsonProperty;

public record ApiErrorResponse(@JsonProperty("type") String type, @JsonProperty("message") String message) {

}
