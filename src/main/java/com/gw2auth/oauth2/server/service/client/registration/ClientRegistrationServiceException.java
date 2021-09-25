package com.gw2auth.oauth2.server.service.client.registration;

import com.gw2auth.oauth2.server.service.Gw2AuthServiceException;
import org.springframework.http.HttpStatus;

public class ClientRegistrationServiceException extends Gw2AuthServiceException {

    public static final String NOT_FOUND = "Referenced ClientRegistration not found";
    public static final String INVALID_REDIRECT_URI = "The given Redirect-URI is invalid";

    public ClientRegistrationServiceException(String message) {
        super(message);
    }

    public ClientRegistrationServiceException(String message, HttpStatus proposedStatusCode) {
        super(message, proposedStatusCode);
    }
}
