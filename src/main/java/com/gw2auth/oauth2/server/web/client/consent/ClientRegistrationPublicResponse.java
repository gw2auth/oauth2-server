package com.gw2auth.oauth2.server.web.client.consent;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.application.client.ApplicationClient;

import java.time.Instant;
import java.util.UUID;

/**
 * The response visible to the public
 */
public record ClientRegistrationPublicResponse(@JsonProperty("creationTime") Instant creationTime,
                                               @JsonProperty("displayName") String displayName,
                                               @JsonProperty("clientId") UUID clientId,
                                               @JsonProperty("apiVersion") int apiVersion) {

    public static ClientRegistrationPublicResponse create(ApplicationClient applicationClient) {
        return new ClientRegistrationPublicResponse(
                applicationClient.creationTime(),
                applicationClient.displayName(),
                applicationClient.id(),
                applicationClient.apiVersion().value()
        );
    }
}
