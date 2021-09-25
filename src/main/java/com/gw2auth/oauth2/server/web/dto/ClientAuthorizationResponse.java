package com.gw2auth.oauth2.server.web.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.apitoken.ApiToken;
import com.gw2auth.oauth2.server.service.client.authorization.ClientAuthorization;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistration;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public record ClientAuthorizationResponse(@JsonProperty("clientRegistration") ClientRegistrationPublicResponse clientRegistration,
                                          @JsonProperty("accountSub") String accountSub,
                                          @JsonProperty("authorizedGw2ApiPermissions") Set<Gw2ApiPermission> authorizedGw2ApiPermissions,
                                          @JsonProperty("tokens") List<Token> tokens) {

    public static ClientAuthorizationResponse create(ClientAuthorization clientAuthorization, ClientRegistration clientRegistration, List<Token> tokens) {
        final Set<Gw2ApiPermission> authorizedGw2ApiPermissions = clientAuthorization.authorizedScopes().stream()
                .flatMap((scope) -> Gw2ApiPermission.fromOAuth2(scope).stream())
                .collect(Collectors.toSet());

        return new ClientAuthorizationResponse(ClientRegistrationPublicResponse.create(clientRegistration), clientAuthorization.accountSub().toString(), authorizedGw2ApiPermissions, tokens);
    }

    public record Token(@JsonProperty("gw2AccountId") String gw2AccountId, @JsonProperty("displayName") String displayName, @JsonProperty("expirationTime") Instant expirationTime) {

        public static Token create(ApiToken apiToken, ClientAuthorization.Token token) {
            return new Token(apiToken.gw2AccountId(), apiToken.displayName(), token.expirationTime());
        }
    }
}
