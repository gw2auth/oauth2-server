package com.gw2auth.oauth2.server.service.gw2account.apitoken;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface Gw2AccountApiTokenService {

    List<Gw2AccountApiToken> getApiTokens(UUID accountId);
    Optional<Gw2AccountApiToken> getApiToken(UUID accountId, UUID gw2AccountId);
    List<Gw2AccountApiToken> getApiTokens(UUID accountId, Collection<UUID> gw2AccountIds);
    Gw2AccountApiToken addOrUpdateApiToken(UUID accountId, String gw2ApiToken);

    void deleteApiToken(UUID accountId, UUID gw2AccountId);

    void updateApiTokensValid(Instant lastValidCheckTime, Collection<Gw2AccountApiTokenValidUpdate> updates);
}
