package com.gw2auth.oauth2.server.service.summary;

public record ApplicationSummary(long accounts, long apiTokens, long verifiedGw2Accounts, long clientRegistrations, long clientAuthorizations) {
}
