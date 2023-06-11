package com.gw2auth.oauth2.server.web.client.consent;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.OAuth2Scope;
import com.gw2auth.oauth2.server.service.application.account.ApplicationAccount;
import com.gw2auth.oauth2.server.service.application.client.ApplicationClient;
import com.gw2auth.oauth2.server.service.application.client.account.ApplicationClientAccount;

import java.util.Set;

public record ClientConsentResponse(@JsonProperty("clientRegistration") ClientRegistrationPublicResponse clientRegistration,
                                    @JsonProperty("accountSub") String accountSub,
                                    @JsonProperty("authorizedScopes") Set<OAuth2Scope> authorizedScopes) {

    public static ClientConsentResponse create(ApplicationClientAccount applicationClientAccount, ApplicationAccount applicationAccount, ApplicationClient applicationClient) {
        return new ClientConsentResponse(
                ClientRegistrationPublicResponse.create(applicationClient),
                applicationAccount.accountSub().toString(),
                applicationClientAccount.authorizedScopes()
        );
    }
}
