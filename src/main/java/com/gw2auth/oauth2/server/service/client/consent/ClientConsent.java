package com.gw2auth.oauth2.server.service.client.consent;

import com.gw2auth.oauth2.server.repository.client.consent.ClientConsentEntity;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

public record ClientConsent(UUID accountId, UUID clientRegistrationId, UUID accountSub, Set<String> authorizedScopes) {

    public static ClientConsent fromEntity(ClientConsentEntity entity) {
        final Set<String> authorizedScopes;

        if (entity.authorizedScopes() == null) {
            authorizedScopes = Set.of();
        } else {
            authorizedScopes = new HashSet<>(entity.authorizedScopes());
        }

        return new ClientConsent(entity.accountId(), entity.clientRegistrationId(), entity.accountSub(), authorizedScopes);
    }
}
