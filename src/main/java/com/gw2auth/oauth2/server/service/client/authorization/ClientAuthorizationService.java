package com.gw2auth.oauth2.server.service.client.authorization;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public interface ClientAuthorizationService {

    String AUTHORIZATION_NAME_PARAM = "name";

    Optional<ClientAuthorization> getClientAuthorization(long accountId, String id);

    List<ClientAuthorization> getClientAuthorizations(long accountId, UUID clientId);

    List<ClientAuthorization> getClientAuthorizations(long accountId, Set<UUID> gw2AccountIds);

    boolean deleteClientAuthorization(long accountId, String id);
}
