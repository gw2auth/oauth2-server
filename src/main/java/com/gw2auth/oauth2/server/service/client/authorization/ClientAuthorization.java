package com.gw2auth.oauth2.server.service.client.authorization;

import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationEntity;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationTokenEntity;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public record ClientAuthorization(String id, UUID accountId, UUID clientRegistrationId, Instant creationTime, Instant lastUpdateTime, String displayName, Set<String> authorizedScopes, Set<UUID> gw2AccountIds) {

    public static ClientAuthorization fromEntity(ClientAuthorizationEntity entity, List<ClientAuthorizationTokenEntity> clientAuthorizationTokenEntities) {
        final Set<UUID> gw2AccountIds = clientAuthorizationTokenEntities.stream()
                .map(ClientAuthorizationTokenEntity::gw2AccountId)
                .collect(Collectors.toSet());

        return new ClientAuthorization(entity.id(), entity.accountId(), entity.clientRegistrationId(), entity.creationTime(), entity.lastUpdateTime(), entity.displayName(), Set.copyOf(entity.authorizedScopes()), gw2AccountIds);
    }
}
