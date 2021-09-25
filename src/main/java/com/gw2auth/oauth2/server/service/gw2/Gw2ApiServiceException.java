package com.gw2auth.oauth2.server.service.gw2;

import com.gw2auth.oauth2.server.service.Gw2AuthServiceException;
import org.springframework.http.HttpStatus;

public class Gw2ApiServiceException extends Gw2AuthServiceException {

    public static final String INVALID_API_TOKEN = "Invalid API-Token";
    public static final String SUBTOKEN_JWT_PARSING_ERROR = "Failed to parse Subtoken JWT";
    public static final String BAD_RESPONSE = "Got a bad response from the GW2-API";

    public Gw2ApiServiceException(String message) {
        super(message);
    }

    public Gw2ApiServiceException(String message, HttpStatus proposedStatusCode) {
        super(message, proposedStatusCode);
    }
}
