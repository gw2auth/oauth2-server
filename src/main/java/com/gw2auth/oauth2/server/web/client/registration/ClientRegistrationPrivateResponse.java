package com.gw2auth.oauth2.server.web.client.registration;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.application.client.ApplicationClient;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

/**
 * The response visible to the owner of this client
 */
public record ClientRegistrationPrivateResponse(@JsonProperty("creationTime") Instant creationTime,
                                                @JsonProperty("displayName") String displayName,
                                                @JsonProperty("clientId") UUID clientId,
                                                @JsonProperty("authorizationGrantTypes") Set<String> authorizationGrantTypes,
                                                @JsonProperty("redirectUris") Set<String> redirectUris,
                                                @JsonProperty("apiVersion") int apiVersion) {

    public static ClientRegistrationPrivateResponse create(ApplicationClient applicationClient) {
        return new ClientRegistrationPrivateResponse(
                applicationClient.creationTime(),
                applicationClient.displayName(),
                applicationClient.id(),
                applicationClient.authorizationGrantTypes(),
                applicationClient.redirectUris(),
                applicationClient.apiVersion().value()
        );
    }
}
