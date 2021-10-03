package com.gw2auth.oauth2.server.service.summary;

public record AccountSummary(long apiTokens, long verifiedGw2Accounts, long clientRegistrations, long clientAuthorizations, long accountFederations) {
}
