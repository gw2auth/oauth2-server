package com.gw2auth.oauth2.server.web.client.registration;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Set;

public record ClientRegistrationCreationRequest(@JsonProperty(value = "displayName", required = true) String displayName,
                                                @JsonProperty(value = "authorizationGrantTypes", required = true) Set<String> authorizationGrantTypes,
                                                @JsonProperty(value = "redirectUris", required = true) Set<String> redirectUris) {
}
