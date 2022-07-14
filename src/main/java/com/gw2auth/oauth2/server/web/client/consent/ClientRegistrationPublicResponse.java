package com.gw2auth.oauth2.server.web.client.consent;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistration;

import java.time.Instant;
import java.util.UUID;

/**
 * The response visible to the public
 */
public record ClientRegistrationPublicResponse(@JsonProperty("creationTime") Instant creationTime,
                                               @JsonProperty("displayName") String displayName,
                                               @JsonProperty("clientId") UUID clientId) {

    public static ClientRegistrationPublicResponse create(ClientRegistration clientRegistration) {
        return new ClientRegistrationPublicResponse(clientRegistration.creationTime(), clientRegistration.displayName(), clientRegistration.id());
    }
}
