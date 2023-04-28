package com.gw2auth.oauth2.server.service.application.client.authorization;

import com.gw2auth.oauth2.server.repository.application.client.authorization.ApplicationClientAuthorizationWithGw2AccountIdsEntity;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

public record ApplicationClientAuthorization(String id, UUID accountId, UUID applicationClientId, Instant creationTime, Instant lastUpdateTime, String displayName, Set<String> authorizedScopes, Set<UUID> gw2AccountIds) {

    public static ApplicationClientAuthorization fromEntity(ApplicationClientAuthorizationWithGw2AccountIdsEntity entity) {
        return new ApplicationClientAuthorization(entity.id(), entity.accountId(), entity.applicationClientId(), entity.creationTime(), entity.lastUpdateTime(), entity.displayName(), Set.copyOf(entity.authorizedScopes()), entity.gw2AccountIds());
    }
}
