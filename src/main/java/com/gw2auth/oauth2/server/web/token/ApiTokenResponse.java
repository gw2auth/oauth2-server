package com.gw2auth.oauth2.server.web.token;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.apitoken.ApiToken;

import java.time.Instant;
import java.util.Set;

public record ApiTokenResponse(@JsonProperty("gw2AccountId") String gw2AccountId,
                               @JsonProperty("creationTime") Instant creationTime,
                               @JsonProperty("gw2ApiToken") String gw2ApiToken,
                               @JsonProperty("displayName") String displayName,
                               @JsonProperty("gw2ApiPermissions") Set<Gw2ApiPermission> gw2ApiPermissions,
                               @JsonProperty("isVerified") boolean isVerified) {

    public static ApiTokenResponse create(ApiToken apiToken, boolean isVerified) {
        return new ApiTokenResponse(apiToken.gw2AccountId(), apiToken.creationTime(), apiToken.gw2ApiToken(), apiToken.displayName(), apiToken.gw2ApiPermissions(), isVerified);
    }

    public record ClientAuthorization(@JsonProperty("displayName") String displayName, @JsonProperty("clientId") String clientId) {

    }
}
