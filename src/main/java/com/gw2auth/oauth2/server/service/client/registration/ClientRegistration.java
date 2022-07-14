package com.gw2auth.oauth2.server.service.client.registration;

import com.gw2auth.oauth2.server.repository.client.registration.ClientRegistrationEntity;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

public record ClientRegistration(UUID id, Instant creationTime, String displayName, Set<String> authorizationGrantTypes, Set<String> redirectUris) {

    public static ClientRegistration fromEntity(ClientRegistrationEntity entity) {
        final Set<String> authorizationGrantTypes;
        final Set<String> redirectUris;

        if (entity.authorizationGrantTypes() == null) {
            authorizationGrantTypes = Set.of();
        } else {
            authorizationGrantTypes = new HashSet<>(entity.authorizationGrantTypes());
        }

        if (entity.redirectUris() == null) {
            redirectUris = Set.of();
        } else {
            redirectUris = Set.copyOf(entity.redirectUris());
        }

        return new ClientRegistration(entity.id(), entity.creationTime(), entity.displayName(), authorizationGrantTypes, redirectUris);
    }
}
