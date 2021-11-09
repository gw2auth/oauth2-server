package com.gw2auth.oauth2.server.web.client.consent;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.client.consent.ClientConsent;
import com.gw2auth.oauth2.server.service.client.consent.ClientConsentService;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistration;

import java.util.Set;
import java.util.stream.Collectors;

public record ClientConsentResponse(@JsonProperty("clientRegistration") ClientRegistrationPublicResponse clientRegistration,
                                    @JsonProperty("accountSub") String accountSub,
                                    @JsonProperty("authorizedGw2ApiPermissions") Set<Gw2ApiPermission> authorizedGw2ApiPermissions,
                                    @JsonProperty("authorizedVerifiedInformation") boolean authorizedVerifiedInformation) {

    public static ClientConsentResponse create(ClientConsent consent, ClientRegistration registration) {
        final Set<Gw2ApiPermission> gw2ApiPermissions = consent.authorizedScopes().stream()
                .flatMap((value) -> Gw2ApiPermission.fromOAuth2(value).stream())
                .collect(Collectors.toSet());

        return new ClientConsentResponse(
                ClientRegistrationPublicResponse.create(registration),
                consent.accountSub().toString(),
                gw2ApiPermissions,
                consent.authorizedScopes().contains(ClientConsentService.GW2AUTH_VERIFIED_SCOPE)
        );
    }
}
