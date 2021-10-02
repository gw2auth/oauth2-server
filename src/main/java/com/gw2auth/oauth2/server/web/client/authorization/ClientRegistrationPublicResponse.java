package com.gw2auth.oauth2.server.web.client.authorization;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistration;

import java.time.Instant;

/**
 * The response visible to the public
 */
public record ClientRegistrationPublicResponse(@JsonProperty("creationTime") Instant creationTime,
                                               @JsonProperty("displayName") String displayName,
                                               @JsonProperty("clientId") String clientId,
                                               @JsonProperty("redirectUri") String redirectUri) {

    public static ClientRegistrationPublicResponse create(ClientRegistration clientRegistration) {
        return new ClientRegistrationPublicResponse(clientRegistration.creationTime(), clientRegistration.displayName(), clientRegistration.clientId(), clientRegistration.redirectUri());
    }
}
