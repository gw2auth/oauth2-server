package com.gw2auth.oauth2.server.service.account;

import com.gw2auth.oauth2.server.service.Gw2AuthServiceException;
import org.springframework.http.HttpStatus;

public class AccountServiceException extends Gw2AuthServiceException {

    public AccountServiceException(String message, HttpStatus proposedStatusCode) {
        super(message, proposedStatusCode);
    }
}
