package com.gw2auth.oauth2.server.web.account;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.account.AccountFederationSession;

import java.time.Instant;

public record AccountSessionResponse(@JsonProperty("id") String id, @JsonProperty("creationTime") Instant creationTime, @JsonProperty("expirationTime") Instant expirationTime) {

    public static AccountSessionResponse create(AccountFederationSession value) {
        return new AccountSessionResponse(value.id(), value.creationTime(), value.expirationTime());
    }
}
