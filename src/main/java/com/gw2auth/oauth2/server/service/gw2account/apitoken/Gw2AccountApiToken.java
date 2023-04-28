package com.gw2auth.oauth2.server.service.gw2account.apitoken;

import com.gw2auth.oauth2.server.repository.gw2account.apitoken.Gw2AccountApiTokenEntity;
import com.gw2auth.oauth2.server.repository.gw2account.apitoken.Gw2AccountApiTokenWithPreferencesEntity;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public record Gw2AccountApiToken(UUID accountId,
                                 UUID gw2AccountId,
                                 Instant creationTime,
                                 String gw2ApiToken,
                                 Set<Gw2ApiPermission> gw2ApiPermissions,
                                 Instant lastValidTime,
                                 Instant lastValidCheckTime,
                                 String displayName,
                                 String orderRank) {

    public static Gw2AccountApiToken fromEntity(Gw2AccountApiTokenWithPreferencesEntity entity) {
        return fromEntity(entity, entity.displayName(), entity.orderRank());
    }

    public static Gw2AccountApiToken fromEntity(Gw2AccountApiTokenEntity entity, String displayName, String orderRank) {
        return new Gw2AccountApiToken(
                entity.accountId(),
                entity.gw2AccountId(),
                entity.creationTime(),
                entity.gw2ApiToken(),
                Gw2ApiPermission.fromBitSet(entity.gw2ApiPermissionsBitSet()),
                entity.lastValidTime(),
                entity.lastValidCheckTime(),
                Optional.ofNullable(displayName).orElse(entity.gw2AccountId().toString()),
                Optional.ofNullable(orderRank).orElse(entity.creationTime().toString())
        );
    }
}
