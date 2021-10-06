package com.gw2auth.oauth2.server.service.client.registration;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public interface ClientRegistrationService {

    String FORCE_CONSENT_SCOPE = "force_consent";

    List<ClientRegistration> getClientRegistrations(long accountId);

    Optional<ClientRegistration> getClientRegistration(long accountId, String clientId);

    List<ClientRegistration> getClientRegistrations(Collection<Long> ids);

    Optional<ClientRegistration> getClientRegistration(String clientId);

    ClientRegistrationCreation createClientRegistration(long accountId, String displayName, Set<String> authorizationGrantTypes, String redirectUri);

    void deleteClientRegistration(long accountId, String clientId);
}
