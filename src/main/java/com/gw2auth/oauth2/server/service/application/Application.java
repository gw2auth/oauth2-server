package com.gw2auth.oauth2.server.service.application;

import com.gw2auth.oauth2.server.repository.application.ApplicationEntity;

import java.time.Instant;
import java.util.UUID;

public record Application(UUID id, UUID accountId, Instant creationTime, String displayName) {

    public static Application fromEntity(ApplicationEntity entity) {
        return new Application(
                entity.id(),
                entity.accountId(),
                entity.creationTime(),
                entity.displayName()
        );
    }
}
