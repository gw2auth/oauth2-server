package com.gw2auth.oauth2.server.service.apitoken;

import org.springframework.http.HttpStatus;

public class ApiTokenOwnershipMismatchException extends ApiTokenServiceException {

    public ApiTokenOwnershipMismatchException() {
        super("This GW2-Account is verified for another account", HttpStatus.NOT_ACCEPTABLE);
    }
}
