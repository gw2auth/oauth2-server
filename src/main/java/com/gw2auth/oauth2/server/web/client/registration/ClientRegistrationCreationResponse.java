package com.gw2auth.oauth2.server.web.client.registration;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.application.client.ApplicationClientCreation;

public record ClientRegistrationCreationResponse(@JsonProperty("clientRegistration") ClientRegistrationPrivateResponse clientRegistration,
                                                 @JsonProperty("clientSecret") String clientSecret) {

    public static ClientRegistrationCreationResponse create(ApplicationClientCreation applicationClientCreation) {
        return new ClientRegistrationCreationResponse(ClientRegistrationPrivateResponse.create(applicationClientCreation), applicationClientCreation.clientSecret());
    }
}
