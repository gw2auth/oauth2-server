package com.gw2auth.oauth2.server.service.client.authorization;

import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationEntity;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationTokenEntity;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public record ClientAuthorization(long accountId, String id, long clientRegistrationId, Instant creationTime, Instant lastUpdateTime, String displayName, Set<String> authorizedScopes, Set<String> gw2AccountIds) {

    public static ClientAuthorization fromEntity(ClientAuthorizationEntity entity, List<ClientAuthorizationTokenEntity> clientAuthorizationTokenEntities) {
        final Set<String> gw2AccountIds = clientAuthorizationTokenEntities.stream()
                .map(ClientAuthorizationTokenEntity::gw2AccountId)
                .collect(Collectors.toSet());

        return new ClientAuthorization(entity.accountId(), entity.id(), entity.clientRegistrationId(), entity.creationTime(), entity.lastUpdateTime(), entity.displayName(), Set.copyOf(entity.authorizedScopes()), gw2AccountIds);
    }
}
