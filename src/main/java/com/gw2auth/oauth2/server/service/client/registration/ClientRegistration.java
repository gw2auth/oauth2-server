package com.gw2auth.oauth2.server.service.client.registration;

import com.gw2auth.oauth2.server.repository.client.registration.ClientRegistrationEntity;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

public record ClientRegistration(long id, Instant creationTime, String displayName, String clientId, Set<String> authorizationGrantTypes, String redirectUri) {

    public static ClientRegistration fromEntity(ClientRegistrationEntity entity) {
        final Set<String> authorizationGrantTypes;

        if (entity.authorizationGrantTypes() == null) {
            authorizationGrantTypes = Set.of();
        } else {
            authorizationGrantTypes = new HashSet<>(entity.authorizationGrantTypes());
        }

        return new ClientRegistration(entity.id(), entity.creationTime(), entity.displayName(), entity.clientId(), authorizationGrantTypes, entity.redirectUri());
    }
}
