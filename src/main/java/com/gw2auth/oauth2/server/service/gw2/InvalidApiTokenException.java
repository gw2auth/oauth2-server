package com.gw2auth.oauth2.server.service.gw2;

import org.springframework.http.HttpStatus;

public class InvalidApiTokenException extends Gw2ApiServiceException {
    public InvalidApiTokenException() {
        super(INVALID_API_TOKEN, HttpStatus.BAD_REQUEST);
    }
}
