package com.gw2auth.oauth2.server.service.summary;

import com.gw2auth.oauth2.server.repository.summary.AccountSummaryEntity;
import com.gw2auth.oauth2.server.repository.summary.ApplicationSummaryEntity;
import com.gw2auth.oauth2.server.repository.summary.SummaryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class SummaryServiceImpl implements SummaryService {

    private final SummaryRepository summaryRepository;

    @Autowired
    public SummaryServiceImpl(SummaryRepository summaryRepository) {
        this.summaryRepository = summaryRepository;
    }

    @Override
    public ApplicationSummary getApplicationSummary() {
        final ApplicationSummaryEntity value = this.summaryRepository.getApplicationSummary();

        return new ApplicationSummary(
                value.accounts(),
                value.apiTokens(),
                value.verifiedGw2Accounts(),
                value.clientRegistrations(),
                value.clientAuthorizations()
        );
    }

    @Override
    public AccountSummary getAccountSummary(long accountId) {
        final AccountSummaryEntity value = this.summaryRepository.getAccountSummary(accountId);

        return new AccountSummary(
                value.apiTokens(),
                value.verifiedGw2Accounts(),
                value.clientRegistrations(),
                value.clientAuthorizations(),
                value.accountFederations()
        );
    }
}
