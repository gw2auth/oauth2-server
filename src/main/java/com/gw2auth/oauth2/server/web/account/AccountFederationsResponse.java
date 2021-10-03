package com.gw2auth.oauth2.server.web.account;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public record AccountFederationsResponse(@JsonProperty("currentAccountFederation") AccountFederationResponse currentAccountFederation,
                                         @JsonProperty("accountFederations") List<AccountFederationResponse> accountFederationResponses) {
}
