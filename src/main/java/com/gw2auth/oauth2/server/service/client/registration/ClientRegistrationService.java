package com.gw2auth.oauth2.server.service.client.registration;

import java.util.*;

public interface ClientRegistrationService {

    List<ClientRegistration> getClientRegistrations(UUID accountId);

    Optional<ClientRegistration> getClientRegistration(UUID accountId, UUID id);

    List<ClientRegistration> getClientRegistrations(Collection<UUID> ids);

    Optional<ClientRegistration> getClientRegistration(UUID id);

    ClientRegistrationCreation createClientRegistration(UUID accountId, String displayName, Set<String> authorizationGrantTypes, Set<String> redirectUris);

    ClientRegistration addRedirectUri(UUID accountId, UUID id, String redirectUri);

    ClientRegistration removeRedirectUri(UUID accountId, UUID id, String redirectUri);

    ClientRegistrationCreation regenerateClientSecret(UUID accountId, UUID id);

    void deleteClientRegistration(UUID accountId, UUID id);
}
