package com.gw2auth.oauth2.server.service.application;

import com.gw2auth.oauth2.server.service.Gw2AuthServiceException;
import org.springframework.http.HttpStatus;

public class ApplicationServiceException extends Gw2AuthServiceException {

    public static final String NOT_FOUND = "The application does not exist";

    public ApplicationServiceException(String message, HttpStatus proposedStatusCode) {
        super(message, proposedStatusCode);
    }
}
