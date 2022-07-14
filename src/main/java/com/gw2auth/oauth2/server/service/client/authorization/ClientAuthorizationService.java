package com.gw2auth.oauth2.server.service.client.authorization;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public interface ClientAuthorizationService {

    String AUTHORIZATION_NAME_PARAM = "name";

    Optional<ClientAuthorization> getClientAuthorization(UUID accountId, String id);

    Optional<ClientAuthorization> getLatestClientAuthorization(UUID accountId, UUID clientRegistrationId, Set<String> scopes);

    List<ClientAuthorization> getClientAuthorizations(UUID accountId, UUID clientRegistrationId);

    List<ClientAuthorization> getClientAuthorizations(UUID accountId, Set<UUID> gw2AccountIds);

    boolean deleteClientAuthorization(UUID accountId, String id);
}
