package com.gw2auth.oauth2.server.service.gw2account.verification;

import com.gw2auth.oauth2.server.service.Gw2AuthServiceException;
import org.springframework.http.HttpStatus;

public class Gw2AccountVerificationServiceException extends Gw2AuthServiceException {

    public static final String CHALLENGE_NOT_FOUND = "The referenced challenge could not be found";
    public static final String INSUFFICIENT_PERMISSIONS = "The given API-Token has not enough permissions";
    public static final String INTERNAL_SERVER_ERROR = "Internal server error";
    public static final String CHALLENGE_ALREADY_STARTED = "The selected challenge has already been started";
    public static final String CHALLENGE_FOR_THIS_GW2_ACCOUNT_ALREADY_STARTED = "You already have a pending challenge for this GW2-Account";
    public static final String GW2_ACCOUNT_ALREADY_VERIFIED = "This GW2-Account is already verified for your GW2Auth-Account";

    public Gw2AccountVerificationServiceException(String message, HttpStatus proposedStatusCode) {
        super(message, proposedStatusCode);
    }
}
