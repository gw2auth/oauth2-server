package com.gw2auth.oauth2.server.web.client.registration;

import com.fasterxml.jackson.annotation.JsonProperty;

public record ClientRegistrationCreationResponse(@JsonProperty("clientRegistration") ClientRegistrationPrivateResponse clientRegistration,
                                                 @JsonProperty("clientSecret") String clientSecret) {

}
