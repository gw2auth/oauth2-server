package com.gw2auth.oauth2.server.web.token;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.apitoken.ApiToken;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistration;

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

    public static ApiTokenResponse create(ApiToken apiToken, boolean isVerified, List<Authorization> authorizations) {
        return new ApiTokenResponse(apiToken.gw2AccountId(), apiToken.creationTime(), apiToken.gw2ApiToken(), apiToken.displayName(), apiToken.gw2ApiPermissions(), apiToken.isValid(), isVerified, authorizations);
    }

    public record Authorization(@JsonProperty("displayName") String displayName, @JsonProperty("clientId") UUID clientId) {

        public static Authorization create(ClientRegistration value) {
            return new Authorization(value.displayName(), value.clientId());
        }
    }
}
