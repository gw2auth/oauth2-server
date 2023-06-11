package com.gw2auth.oauth2.server.service.gw2account;

import com.gw2auth.oauth2.server.repository.gw2account.Gw2AccountEntity;

import java.time.Instant;
import java.util.UUID;

public record Gw2Account(UUID accountId, UUID gw2AccountId, String gw2AccountName, Instant creationTime, String displayName, String orderRank) {

    public static Gw2Account fromEntity(Gw2AccountEntity entity) {
        return new Gw2Account(
                entity.accountId(),
                entity.gw2AccountId(),
                entity.gw2AccountName(),
                entity.creationTime(),
                entity.displayName(),
                entity.orderRank()
        );
    }
}
