package com.gw2auth.oauth2.server.service.account;

import com.gw2auth.oauth2.server.repository.account.AccountWithFederationEntity;

public record AccountSession(Account account, AccountFederation accountFederation, byte[] metadata) {

    public static AccountSession fromEntity(AccountWithFederationEntity entity) {
        return new AccountSession(
                new Account(entity.id(), entity.creationTime()),
                new AccountFederation(entity.issuer(), entity.idAtIssuer()),
                entity.metadata()
        );
    }
}
