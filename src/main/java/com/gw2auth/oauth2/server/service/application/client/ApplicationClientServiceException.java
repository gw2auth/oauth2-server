package com.gw2auth.oauth2.server.service.application.client;

import com.gw2auth.oauth2.server.service.Gw2AuthServiceException;
import org.springframework.http.HttpStatus;

public class ApplicationClientServiceException extends Gw2AuthServiceException {

    public static final String NOT_FOUND = "Referenced ClientRegistration not found";
    public static final String APPLICATION_NOT_FOUND = "The referenced Application could not be found";
    public static final String INVALID_REDIRECT_URI = "The given Redirect-URI is invalid";
    public static final String NOT_ENOUGH_REDIRECT_URIS = "At least one Redirect-URI is required";

    public ApplicationClientServiceException(String message) {
        super(message);
    }

    public ApplicationClientServiceException(String message, HttpStatus proposedStatusCode) {
        super(message, proposedStatusCode);
    }
}
