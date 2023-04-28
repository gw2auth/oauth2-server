package com.gw2auth.oauth2.server.service.application.client;

import java.util.*;

public interface ApplicationClientService {

    List<ApplicationClient> getApplicationClients(UUID accountId);
    Optional<ApplicationClient> getApplicationClient(UUID accountId, UUID id);
    List<ApplicationClient> getApplicationClients(Collection<UUID> ids);
    ApplicationClientCreation createApplicationClient(UUID accountId, UUID applicationId, String displayName, Set<String> authorizationGrantTypes, Set<String> redirectUris);
    ApplicationClient addRedirectUri(UUID accountId, UUID id, String redirectUri);

    ApplicationClient removeRedirectUri(UUID accountId, UUID id, String redirectUri);

    ApplicationClientCreation regenerateClientSecret(UUID accountId, UUID id);

    void deleteClientRegistration(UUID accountId, UUID id);
}
