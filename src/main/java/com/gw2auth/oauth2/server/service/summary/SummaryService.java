package com.gw2auth.oauth2.server.service.summary;

public interface SummaryService {

    ApplicationSummary getApplicationSummary();
    AccountSummary getAccountSummary(long accountId);
}
