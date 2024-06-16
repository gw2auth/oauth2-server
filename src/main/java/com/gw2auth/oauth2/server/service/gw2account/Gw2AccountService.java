package com.gw2auth.oauth2.server.service.gw2account;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

public interface Gw2AccountService {

    Gw2Account getOrCreateGw2Account(UUID accountId, UUID gw2AccountId, String gw2AccountName, String displayName);
    List<Gw2AccountWithOptionalApiToken> getWithOptionalApiTokens(UUID accountId, Collection<UUID> gw2AccountIds);
    List<Gw2AccountWithApiToken> getWithApiTokens(UUID accountId);
}
