package com.gw2auth.oauth2.server.web.application;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.summary.ApplicationSummary;

public record ApplicationSummaryResponse(@JsonProperty("accounts") long accounts,
                                         @JsonProperty("apiTokens") long apiTokens,
                                         @JsonProperty("verifiedGw2Accounts") long verifiedGw2Accounts,
                                         @JsonProperty("clientRegistrations") long clientRegistrations,
                                         @JsonProperty("clientAuthorizations") long clientAuthorizations) {

    public static ApplicationSummaryResponse create(ApplicationSummary value) {
        return new ApplicationSummaryResponse(value.accounts(), value.apiTokens(), value.verifiedGw2Accounts(), value.clientRegistrations(), value.clientAuthorizations());
    }
}
