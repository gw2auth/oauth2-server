package com.gw2auth.oauth2.server.web.token;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.application.client.ApplicationClient;
import com.gw2auth.oauth2.server.service.gw2account.Gw2Account;
import com.gw2auth.oauth2.server.service.gw2account.apitoken.Gw2AccountApiToken;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

public record ApiTokenResponse(@JsonProperty("gw2AccountId") UUID gw2AccountId,
                               @JsonProperty("creationTime") Instant creationTime,
                               @JsonProperty("gw2ApiToken") String gw2ApiToken,
                               @JsonProperty("displayName") String displayName,
                               @JsonProperty("gw2ApiPermissions") Set<Gw2ApiPermission> gw2ApiPermissions,
                               @JsonProperty("isValid") boolean isValid,
                               @JsonProperty("isVerified") boolean isVerified,
                               @JsonProperty("authorizations") List<Authorization> authorizations) {

    public static ApiTokenResponse create(Gw2Account account, Gw2AccountApiToken token, boolean isVerified, List<Authorization> authorizations) {
        return create(token, account.displayName(), isVerified, authorizations);
    }

    public static ApiTokenResponse create(Gw2AccountApiToken value, String displayName, boolean isVerified, List<Authorization> authorizations) {
        final boolean isValid = Duration.between(value.lastValidTime(), value.lastValidCheckTime()).toSeconds() < 1L;
        return new ApiTokenResponse(value.gw2AccountId(), value.creationTime(), value.gw2ApiToken(), displayName, value.gw2ApiPermissions(), isValid, isVerified, authorizations);
    }

    public record Authorization(@JsonProperty("displayName") String displayName, @JsonProperty("clientId") UUID clientId) {

        public static Authorization create(ApplicationClient value) {
            return new Authorization(value.displayName(), value.id());
        }
    }
}
