package com.gw2auth.oauth2.server.service;

import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpStatus;

import java.util.Optional;

public class Gw2AuthServiceException extends RuntimeException {

    private final @Nullable HttpStatus proposedStatusCode;

    public Gw2AuthServiceException(String message) {
        this(message, null);
    }

    public Gw2AuthServiceException(String message, @Nullable HttpStatus proposedStatusCode) {
        super(message);
        this.proposedStatusCode = proposedStatusCode;
    }

    public String getType() {
        return getClass().getSimpleName();
    }

    public Optional<HttpStatus> getProposedStatusCode() {
        return Optional.ofNullable(this.proposedStatusCode);
    }
}
