package com.gw2auth.oauth2.server.service.client.registration;

import java.util.*;

public interface ClientRegistrationService {

    List<ClientRegistration> getClientRegistrations(long accountId);

    Optional<ClientRegistration> getClientRegistration(long accountId, UUID clientId);

    List<ClientRegistration> getClientRegistrations(Collection<Long> ids);

    Optional<ClientRegistration> getClientRegistration(UUID clientId);

    ClientRegistrationCreation createClientRegistration(long accountId, String displayName, Set<String> authorizationGrantTypes, Set<String> redirectUris);

    ClientRegistration addRedirectUri(long accountId, UUID clientId, String redirectUri);

    ClientRegistration removeRedirectUri(long accountId, UUID clientId, String redirectUri);

    ClientRegistrationCreation regenerateClientSecret(long accountId, UUID clientId);

    void deleteClientRegistration(long accountId, UUID clientId);
}
