package com.gw2auth.oauth2.server.service.gw2account;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface Gw2AccountService {

    Gw2Account getOrCreateGw2Account(UUID accountId, UUID gw2AccountId, String gw2AccountName, String displayName);
    Optional<Gw2Account> getGw2Account(UUID accountId, UUID gw2AccountId);
    List<Gw2AccountWithOptionalApiToken> getWithOptionalApiTokens(UUID accountId, Collection<UUID> gw2AccountIds);
    Optional<Gw2AccountWithApiToken> getWithApiToken(UUID accountId, UUID gw2AccountId);
    List<Gw2AccountWithApiToken> getWithApiTokens(UUID accountId);
    List<Gw2AccountWithApiToken> getWithApiTokens(UUID accountId, Collection<UUID> gw2AccountIds);
    void updateDisplayName(UUID accountId, UUID gw2AccountId, String displayName);
    void updateOrderBetween(UUID accountId, UUID gw2AccountId, String first, String second);
}
