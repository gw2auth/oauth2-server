package com.gw2auth.oauth2.server.service.application.client;

import com.gw2auth.oauth2.server.repository.application.client.ApplicationClientEntity;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

public class ApplicationClientCreation extends ApplicationClient {

    private final String clientSecret;

    public ApplicationClientCreation(UUID id, UUID applicationId, Instant creationTime, String displayName, Set<String> authorizationGrantTypes, Set<String> redirectUris, boolean requiresApproval, String clientSecret) {
        super(id, applicationId, creationTime, displayName, authorizationGrantTypes, redirectUris, requiresApproval);
        this.clientSecret = clientSecret;
    }

    public static ApplicationClientCreation fromEntity(ApplicationClientEntity entity, String clientSecret) {
        return new ApplicationClientCreation(
                entity.id(),
                entity.applicationId(),
                entity.creationTime(),
                entity.displayName(),
                entity.authorizationGrantTypes(),
                entity.redirectUris(),
                entity.requiresApproval(),
                clientSecret
        );
    }

    public String clientSecret() {
        return this.clientSecret;
    }
}
