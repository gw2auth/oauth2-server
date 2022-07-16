package com.gw2auth.oauth2.server.service.client.consent;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ClientConsentService {

    String GW2AUTH_VERIFIED_SCOPE = "gw2auth:verified";

    List<ClientConsent> getClientConsents(UUID accountId);

    Optional<ClientConsent> getClientConsent(UUID accountId, UUID clientRegistrationId);

    void createEmptyClientConsentIfNotExists(UUID accountId, UUID clientRegistrationId);

    void deleteClientConsent(UUID accountId, UUID clientRegistrationId);
}
