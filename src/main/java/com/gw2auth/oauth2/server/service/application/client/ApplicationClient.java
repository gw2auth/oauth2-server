package com.gw2auth.oauth2.server.service.application.client;

import com.gw2auth.oauth2.server.repository.application.client.ApplicationClientEntity;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

public class ApplicationClient {
    private final UUID id;
    private final UUID applicationId;
    private final Instant creationTime;
    private final String displayName;
    private final Set<String> authorizationGrantTypes;
    private final Set<String> redirectUris;
    private final boolean requiresApproval;

    public ApplicationClient(UUID id,
                             UUID applicationId,
                             Instant creationTime,
                             String displayName,
                             Set<String> authorizationGrantTypes,
                             Set<String> redirectUris,
                             boolean requiresApproval) {
        this.id = id;
        this.applicationId = applicationId;
        this.creationTime = creationTime;
        this.displayName = displayName;
        this.authorizationGrantTypes = authorizationGrantTypes;
        this.redirectUris = redirectUris;
        this.requiresApproval = requiresApproval;
    }

    public static ApplicationClient fromEntity(ApplicationClientEntity entity) {
        return new ApplicationClient(
                entity.id(),
                entity.applicationId(),
                entity.creationTime(),
                entity.displayName(),
                entity.authorizationGrantTypes(),
                entity.redirectUris(),
                entity.requiresApproval()
        );
    }

    public UUID id() {
        return this.id;
    }

    public UUID applicationId() {
        return this.applicationId;
    }

    public Instant creationTime() {
        return this.creationTime;
    }

    public String displayName() {
        return this.displayName;
    }

    public Set<String> authorizationGrantTypes() {
        return this.authorizationGrantTypes;
    }

    public Set<String> redirectUris() {
        return this.redirectUris;
    }

    public boolean requiresApproval() {
        return this.requiresApproval;
    }
}
