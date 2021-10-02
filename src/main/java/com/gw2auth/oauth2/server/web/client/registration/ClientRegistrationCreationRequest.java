package com.gw2auth.oauth2.server.web.client.registration;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Set;

public record ClientRegistrationCreationRequest(@JsonProperty("displayName") String displayName,
                                                @JsonProperty("authorizationGrantTypes") Set<String> authorizationGrantTypes,
                                                @JsonProperty("redirectUri") String redirectUri) {
}
