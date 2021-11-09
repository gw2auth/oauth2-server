package com.gw2auth.oauth2.server.web.client.authorization;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.client.authorization.ClientAuthorization;
import com.gw2auth.oauth2.server.service.client.consent.ClientConsentService;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public record ClientAuthorizationResponse(@JsonProperty("id") String id,
                                          @JsonProperty("creationTime") Instant creationTime,
                                          @JsonProperty("lastUpdateTime") Instant lastUpdateTime,
                                          @JsonProperty("displayName") String displayName,
                                          @JsonProperty("authorizedGw2ApiPermissions") Set<Gw2ApiPermission> authorizedGw2ApiPermissions,
                                          @JsonProperty("authorizedVerifiedInformation") boolean authorizedVerifiedInformation,
                                          @JsonProperty("tokens") List<Token> tokens) {

    public static ClientAuthorizationResponse create(ClientAuthorization authorization, List<Token> tokens) {
        final Set<Gw2ApiPermission> gw2ApiPermissions = authorization.authorizedScopes().stream()
                .flatMap((value) -> Gw2ApiPermission.fromOAuth2(value).stream())
                .collect(Collectors.toSet());

        return new ClientAuthorizationResponse(authorization.id(), authorization.creationTime(), authorization.lastUpdateTime(), authorization.displayName(), gw2ApiPermissions, authorization.authorizedScopes().contains(ClientConsentService.GW2AUTH_VERIFIED_SCOPE), tokens);
    }

    public record Token(@JsonProperty("gw2AccountId") String gw2AccountId,
                        @JsonProperty("displayName") String displayName) {

    }
}
