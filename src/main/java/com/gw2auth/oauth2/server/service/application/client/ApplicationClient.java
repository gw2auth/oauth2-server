package com.gw2auth.oauth2.server.service.application.client;

import com.gw2auth.oauth2.server.repository.application.client.ApplicationClientEntity;
import com.gw2auth.oauth2.server.service.OAuth2ClientApiVersion;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

public record ApplicationClient(UUID id,
                                UUID applicationId,
                                Instant creationTime,
                                String displayName,
                                Set<String> authorizationGrantTypes,
                                Set<String> redirectUris,
                                boolean requiresApproval,
                                OAuth2ClientApiVersion apiVersion) {

    public static ApplicationClient fromEntity(ApplicationClientEntity entity) {
        return new ApplicationClient(
                entity.id(),
                entity.applicationId(),
                entity.creationTime(),
                entity.displayName(),
                entity.authorizationGrantTypes(),
                entity.redirectUris(),
                entity.requiresApproval(),
                OAuth2ClientApiVersion.fromValueRequired(entity.apiVersion())
        );
    }
}
