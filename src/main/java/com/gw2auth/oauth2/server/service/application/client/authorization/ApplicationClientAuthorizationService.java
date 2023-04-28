package com.gw2auth.oauth2.server.service.application.client.authorization;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ApplicationClientAuthorizationService {

    String AUTHORIZATION_NAME_PARAM = "name";

    List<ApplicationClientAuthorization> getApplicationClientAuthorizations(UUID accountId, UUID applicationClientId);
    List<ApplicationClientAuthorization> getApplicationClientAuthorizations(UUID accountId, Collection<UUID> gw2AccountIds);
    Optional<ApplicationClientAuthorization> getApplicationClientAuthorization(UUID accountId, String id);
    void deleteApplicationClientAuthorization(UUID accountId, String id);
}
