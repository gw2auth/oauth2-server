package com.gw2auth.oauth2.server.service.gw2account.apitoken;

import org.springframework.http.HttpStatus;

public class Gw2AccountApiTokenOwnershipMismatchException extends Gw2AccountApiTokenServiceException {

    public Gw2AccountApiTokenOwnershipMismatchException() {
        super("This GW2-Account is verified for another account", HttpStatus.NOT_ACCEPTABLE);
    }
}
