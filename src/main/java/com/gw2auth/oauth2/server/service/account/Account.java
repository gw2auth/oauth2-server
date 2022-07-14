package com.gw2auth.oauth2.server.service.account;

import com.gw2auth.oauth2.server.repository.account.AccountEntity;

import java.time.Instant;
import java.util.UUID;

public record Account(UUID id, Instant creationTime) {

    public static Account fromEntity(AccountEntity entity) {
        return new Account(entity.id(), entity.creationTime());
    }
}
