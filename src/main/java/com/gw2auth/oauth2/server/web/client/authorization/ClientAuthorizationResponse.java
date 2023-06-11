package com.gw2auth.oauth2.server.web.client.authorization;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.OAuth2Scope;
import com.gw2auth.oauth2.server.service.application.client.authorization.ApplicationClientAuthorization;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

public record ClientAuthorizationResponse(@JsonProperty("id") String id,
                                          @JsonProperty("creationTime") Instant creationTime,
                                          @JsonProperty("lastUpdateTime") Instant lastUpdateTime,
                                          @JsonProperty("displayName") String displayName,
                                          @JsonProperty("authorizedScopes") Set<OAuth2Scope> authorizedScopes,
                                          @JsonProperty("tokens") List<Token> tokens) {

    public static ClientAuthorizationResponse create(ApplicationClientAuthorization authorization, List<Token> tokens) {
        return new ClientAuthorizationResponse(
                authorization.id(),
                authorization.creationTime(),
                authorization.lastUpdateTime(),
                authorization.displayName(),
                authorization.authorizedScopes(),
                tokens
        );
    }

    public record Token(@JsonProperty("gw2AccountId") UUID gw2AccountId,
                        @JsonProperty("displayName") String displayName) {

    }
}
