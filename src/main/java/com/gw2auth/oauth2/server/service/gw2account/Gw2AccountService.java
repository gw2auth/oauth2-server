package com.gw2auth.oauth2.server.service.gw2account;

import java.util.UUID;

public interface Gw2AccountService {

    Gw2Account getOrCreateGw2Account(UUID accountId, UUID gw2AccountId, String displayName);
    void updateDisplayName(UUID accountId, UUID gw2AccountId, String displayName);
    void updateOrderBetween(UUID accountId, UUID gw2AccountId, String first, String second);
}
