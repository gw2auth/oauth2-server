package com.gw2auth.oauth2.server.web.client.registration;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistrationCreation;

public record ClientRegistrationCreationResponse(@JsonProperty("clientRegistration") ClientRegistrationPrivateResponse clientRegistration,
                                                 @JsonProperty("clientSecret") String clientSecret) {

    public static ClientRegistrationCreationResponse create(ClientRegistrationCreation clientRegistrationCreation) {
        return new ClientRegistrationCreationResponse(ClientRegistrationPrivateResponse.create(clientRegistrationCreation.clientRegistration()), clientRegistrationCreation.clientSecret());
    }
}
