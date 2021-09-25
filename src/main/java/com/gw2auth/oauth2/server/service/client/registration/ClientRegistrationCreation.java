package com.gw2auth.oauth2.server.service.client.registration;

import com.gw2auth.oauth2.server.repository.client.registration.ClientRegistrationEntity;

public record ClientRegistrationCreation(ClientRegistration clientRegistration, String clientSecret) {

    public static ClientRegistrationCreation fromEntity(ClientRegistrationEntity entity, String clientSecret) {
        return new ClientRegistrationCreation(ClientRegistration.fromEntity(entity), clientSecret);
    }
}
