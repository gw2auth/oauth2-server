package com.gw2auth.oauth2.server.web.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.account.AccountFederation;

public record AccountFederationResponse(@JsonProperty("issuer") String issuer, @JsonProperty("idAtIssuer") String idAtIssuer) {

    public static AccountFederationResponse create(AccountFederation value) {
        return new AccountFederationResponse(value.issuer(), value.idAtIssuer());
    }
}
