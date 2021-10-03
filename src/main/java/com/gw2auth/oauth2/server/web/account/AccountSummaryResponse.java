package com.gw2auth.oauth2.server.web.account;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.summary.AccountSummary;

public record AccountSummaryResponse(@JsonProperty("apiTokens") long apiTokens,
                                     @JsonProperty("verifiedGw2Accounts") long verifiedGw2Accounts,
                                     @JsonProperty("clientRegistrations") long clientRegistrations,
                                     @JsonProperty("clientAuthorizations") long clientAuthorizations,
                                     @JsonProperty("accountFederations") long accountFederations) {

    public static AccountSummaryResponse create(AccountSummary value) {
        return new AccountSummaryResponse(value.apiTokens(), value.verifiedGw2Accounts(), value.clientRegistrations(), value.clientAuthorizations(), value.accountFederations());
    }
}
