package com.gw2auth.oauth2.server.service.account;

import com.gw2auth.oauth2.server.repository.account.AccountFederationEntity;

public record AccountFederation(String issuer, String idAtIssuer) {

    public static AccountFederation fromEntity(AccountFederationEntity entity) {
        return new AccountFederation(entity.issuer(), entity.idAtIssuer());
    }
}
