package com.gw2auth.oauth2.server.service.gw2account.apitoken;

import com.gw2auth.oauth2.server.service.Gw2AuthServiceException;
import org.springframework.http.HttpStatus;

public class Gw2AccountApiTokenServiceException extends Gw2AuthServiceException {

    public static final String MISSING_ACCOUNT_PERMISSION = "Given API-Token is missing 'account'-Permission";
    public static final String GW2_ACCOUNT_ID_MISMATCH = "Given API-Token does not belong to the same GuildWars2-Account";
    public static final String API_TOKEN_NOT_FOUND = "The referenced API-Token could not be found";
    public static final String API_TOKEN_ALREADY_EXISTS = "The referenced API-Token already exists";
    public static final String API_TOKEN_NOT_ALLOWED = "You're not allowed to add an API-Token for this GuildWars2-Account";

    public Gw2AccountApiTokenServiceException(String message) {
        super(message);
    }

    public Gw2AccountApiTokenServiceException(String message, HttpStatus proposedStatusCode) {
        super(message, proposedStatusCode);
    }
}
