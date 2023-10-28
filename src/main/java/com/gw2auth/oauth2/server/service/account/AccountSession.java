package com.gw2auth.oauth2.server.service.account;

import com.gw2auth.oauth2.server.repository.account.AccountWithSessionEntity;

import java.time.Instant;

public record AccountSession(Account account, AccountFederation accountFederation, Instant sessionCreationTime, byte[] metadata) {

    public static AccountSession fromEntity(AccountWithSessionEntity entity) {
        return new AccountSession(
                Account.fromEntity(entity.account()),
                new AccountFederation(entity.session().issuer(), entity.session().idAtIssuer()),
                entity.session().creationTime(),
                entity.session().metadata()
        );
    }
}
