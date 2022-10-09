package com.gw2auth.oauth2.server.service.summary;

import com.gw2auth.oauth2.server.repository.summary.AccountSummaryEntity;
import com.gw2auth.oauth2.server.repository.summary.ApplicationSummaryEntity;
import com.gw2auth.oauth2.server.repository.summary.ClientSummaryEntity;
import com.gw2auth.oauth2.server.repository.summary.SummaryRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.util.Objects;
import java.util.UUID;

@Service
public class SummaryServiceImpl implements SummaryService {

    private final SummaryRepository summaryRepository;
    private volatile Clock clock;

    @Autowired
    public SummaryServiceImpl(SummaryRepository summaryRepository) {
        this.summaryRepository = summaryRepository;
        this.clock = Clock.systemUTC();
    }

    public void setClock(Clock clock) {
        this.clock = Objects.requireNonNull(clock);
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
    public AccountSummary getAccountSummary(UUID accountId) {
        final AccountSummaryEntity value = this.summaryRepository.getAccountSummary(accountId);

        return new AccountSummary(
                value.apiTokens(),
                value.verifiedGw2Accounts(),
                value.clientRegistrations(),
                value.clientAuthorizations(),
                value.accountFederations()
        );
    }

    @Override
    public ClientSummary getClientSummary(UUID clientId) {
        final ClientSummaryEntity value = this.summaryRepository.getClientSummary(clientId, this.clock.instant());

        return new ClientSummary(
                value.accounts(),
                value.gw2Accounts(),
                value.authPast1d(),
                value.authPast3d(),
                value.authPast7d(),
                value.authPast30d()
        );
    }
}
