package com.gw2auth.oauth2.server.service.account;

import com.gw2auth.oauth2.server.repository.account.AccountFederationSessionEntity;

import java.time.Instant;

public record AccountFederationSession(String id, Instant creationTime, Instant expirationTime) {

    public static AccountFederationSession fromEntity(AccountFederationSessionEntity entity) {
        return new AccountFederationSession(entity.id(), entity.creationTime(), entity.expirationTime());
    }
}
