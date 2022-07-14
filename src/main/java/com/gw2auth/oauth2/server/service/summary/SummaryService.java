package com.gw2auth.oauth2.server.service.summary;

import java.util.UUID;

public interface SummaryService {

    ApplicationSummary getApplicationSummary();
    AccountSummary getAccountSummary(UUID accountId);
}
