package com.gw2auth.oauth2.server.web.oauth2.consent;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.OAuth2Scope;
import com.gw2auth.oauth2.server.service.gw2account.Gw2Account;
import com.gw2auth.oauth2.server.service.gw2account.apitoken.Gw2AccountApiToken;
import com.gw2auth.oauth2.server.web.client.consent.ClientRegistrationPublicResponse;
import org.springframework.util.MultiValueMap;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.UUID;

public record OAuth2ConsentInfoResponse(@JsonProperty("clientRegistration") ClientRegistrationPublicResponse clientRegistration,
                                        @JsonProperty("requestedScopes") Set<OAuth2Scope> requestedScopes,
                                        @JsonProperty("submitFormUri") String submitFormUri,
                                        @JsonProperty("submitFormParameters") MultiValueMap<String, String> submitFormParameters,
                                        @JsonProperty("cancelUri") String cancelUri,
                                        @JsonProperty("apiTokensWithSufficientPermissions") List<MinimalApiToken> apiTokensWithSufficientPermissionResponses,
                                        @JsonProperty("apiTokensWithInsufficientPermissions") List<MinimalApiToken> apiTokensWithInsufficientPermissionResponses,
                                        @JsonProperty("previouslyConsentedGw2AccountIds") Set<UUID> previouslyConsentedGw2AccountIds,
                                        @JsonProperty("containsAnyGw2AccountRelatedScopes") boolean containsAnyGw2AccountRelatedScopes) {

    public record MinimalApiToken(@JsonProperty("gw2AccountId") UUID gw2AccountId,
                                  @JsonProperty("gw2ApiToken") String gw2ApiToken,
                                  @JsonProperty("displayName") String displayName,
                                  @JsonProperty("isValid") boolean isValid,
                                  @JsonProperty("isVerified") boolean isVerified) {

        public static MinimalApiToken create(Gw2Account account, Gw2AccountApiToken token, boolean isVerified) {
            final boolean isValid = Duration.between(token.lastValidTime(), token.lastValidCheckTime()).toSeconds() < 1L;
            return new MinimalApiToken(account.gw2AccountId(), token.gw2ApiToken(), account.displayName(), isValid, isVerified);
        }
    }
}
