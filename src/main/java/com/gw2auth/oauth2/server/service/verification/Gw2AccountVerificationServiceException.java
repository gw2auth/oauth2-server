package com.gw2auth.oauth2.server.service.verification;

import com.gw2auth.oauth2.server.service.Gw2AuthServiceException;
import org.springframework.http.HttpStatus;

public class Gw2AccountVerificationServiceException extends Gw2AuthServiceException {

    public static final String CHALLENGE_NOT_FOUND = "The referenced challenge could not be found";
    public static final String INSUFFICIENT_PERMISSIONS = "The given API-Token has not enough permissions";
    public static final String TOO_EARLY = "Please wait until the API update time is over";
    public static final String INTERNAL_SERVER_ERROR = "Internal server error";

    public Gw2AccountVerificationServiceException(String message) {
        super(message);
    }

    public Gw2AccountVerificationServiceException(String message, HttpStatus proposedStatusCode) {
        super(message, proposedStatusCode);
    }
}
