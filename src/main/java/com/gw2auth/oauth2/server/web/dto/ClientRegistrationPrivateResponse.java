package com.gw2auth.oauth2.server.web.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistration;

import java.time.Instant;
import java.util.Set;

/**
 * The response visible to the owner of this client
 */
public record ClientRegistrationPrivateResponse(@JsonProperty("creationTime") Instant creationTime,
                                                @JsonProperty("displayName") String displayName,
                                                @JsonProperty("clientId") String clientId,
                                                @JsonProperty("authorizationGrantTypes") Set<String> authorizationGrantTypes,
                                                @JsonProperty("redirectUri") String redirectUri) {

    public static ClientRegistrationPrivateResponse create(ClientRegistration clientRegistration) {
        return new ClientRegistrationPrivateResponse(clientRegistration.creationTime(), clientRegistration.displayName(), clientRegistration.clientId(), clientRegistration.authorizationGrantTypes(), clientRegistration.redirectUri());
    }
}
