package com.gw2auth.oauth2.server.service.application.client.authorization;

import com.gw2auth.oauth2.server.repository.application.client.authorization.ApplicationClientAuthorizationWithGw2AccountIdsEntity;
import com.gw2auth.oauth2.server.service.OAuth2Scope;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public record ApplicationClientAuthorization(String id,
                                             UUID accountId,
                                             UUID applicationClientId,
                                             Instant creationTime,
                                             Instant lastUpdateTime,
                                             String displayName,
                                             Set<OAuth2Scope> authorizedScopes,
                                             Set<UUID> gw2AccountIds) {

    public static ApplicationClientAuthorization fromEntity(ApplicationClientAuthorizationWithGw2AccountIdsEntity entity) {
        return new ApplicationClientAuthorization(
                entity.authorization().id(),
                entity.authorization().accountId(),
                entity.authorization().applicationClientId(),
                entity.authorization().creationTime(),
                entity.authorization().lastUpdateTime(),
                entity.authorization().displayName(),
                entity.authorization().authorizedScopes().stream()
                        .map(OAuth2Scope::fromOAuth2Required)
                        .collect(Collectors.toUnmodifiableSet()),
                entity.gw2AccountIds()
        );
    }
}
