package com.gw2auth.oauth2.server.web.client.consent;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.application.account.ApplicationAccount;
import com.gw2auth.oauth2.server.service.application.client.ApplicationClient;
import com.gw2auth.oauth2.server.service.application.client.account.ApplicationClientAccount;
import com.gw2auth.oauth2.server.service.application.client.account.ApplicationClientAccountService;

import java.util.Set;
import java.util.stream.Collectors;

public record ClientConsentResponse(@JsonProperty("clientRegistration") ClientRegistrationPublicResponse clientRegistration,
                                    @JsonProperty("accountSub") String accountSub,
                                    @JsonProperty("authorizedGw2ApiPermissions") Set<Gw2ApiPermission> authorizedGw2ApiPermissions,
                                    @JsonProperty("authorizedVerifiedInformation") boolean authorizedVerifiedInformation) {

    public static ClientConsentResponse create(ApplicationClientAccount applicationClientAccount, ApplicationAccount applicationAccount, ApplicationClient applicationClient) {
        final Set<Gw2ApiPermission> gw2ApiPermissions = applicationClientAccount.authorizedScopes().stream()
                .flatMap((value) -> Gw2ApiPermission.fromOAuth2(value).stream())
                .collect(Collectors.toSet());

        return new ClientConsentResponse(
                ClientRegistrationPublicResponse.create(applicationClient),
                applicationAccount.accountSub().toString(),
                gw2ApiPermissions,
                applicationClientAccount.authorizedScopes().contains(ApplicationClientAccountService.GW2AUTH_VERIFIED_SCOPE)
        );
    }
}
