package com.gw2auth.oauth2.server.service.apitoken;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

public interface ApiTokenService {

    List<ApiToken> getApiTokens(UUID accountId);

    List<ApiToken> getApiTokens(UUID accountId, Collection<UUID> gw2AccountIds);

    ApiToken updateApiToken(UUID accountId, UUID gw2AccountId, String gw2ApiToken, String displayName);

    ApiToken addApiToken(UUID accountId, String gw2ApiToken);

    void deleteApiToken(UUID accountId, UUID gw2AccountId);

    void updateApiTokensValid(Instant lastValidCheckTime, Collection<ApiTokenValidityUpdate> updates);
}
