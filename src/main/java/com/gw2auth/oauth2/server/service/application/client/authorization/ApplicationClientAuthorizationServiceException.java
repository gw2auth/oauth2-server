package com.gw2auth.oauth2.server.service.application.client.authorization;

import com.gw2auth.oauth2.server.service.Gw2AuthServiceException;
import org.springframework.http.HttpStatus;

public class ApplicationClientAuthorizationServiceException extends Gw2AuthServiceException {

    public static final String NOT_FOUND = "The authorization was not found";

    public ApplicationClientAuthorizationServiceException(String message, HttpStatus proposedStatusCode) {
        super(message, proposedStatusCode);
    }
}
