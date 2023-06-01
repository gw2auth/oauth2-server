package com.gw2auth.oauth2.server.service.summary;

import com.gw2auth.oauth2.server.repository.summary.AccountSummaryEntity;
import com.gw2auth.oauth2.server.repository.summary.ApplicationSummaryEntity;
import com.gw2auth.oauth2.server.repository.summary.ClientSummaryEntity;
import com.gw2auth.oauth2.server.repository.summary.SummaryRepository;
import com.gw2auth.oauth2.server.service.Clocked;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

@Service
public class SummaryServiceImpl implements SummaryService, Clocked {

    private final SummaryRepository summaryRepository;
    private final AtomicReference<ApplicationSummaryEntity> applicationSummaryEntity;
    private volatile Clock clock;

    @Autowired
    public SummaryServiceImpl(SummaryRepository summaryRepository, MeterRegistry meterRegistry) {
        this.summaryRepository = summaryRepository;
        this.applicationSummaryEntity = new AtomicReference<>(this.summaryRepository.getApplicationSummary());
        this.clock = Clock.systemUTC();

        meterRegistry.gauge("gw2auth_registered_accounts", this.applicationSummaryEntity, (v) -> v.get().accounts());
        meterRegistry.gauge("gw2auth_api_tokens", this.applicationSummaryEntity, (v) -> v.get().apiTokens());
        meterRegistry.gauge("gw2auth_verified_gw2_accounts", this.applicationSummaryEntity, (v) -> v.get().verifiedGw2Accounts());
        meterRegistry.gauge("gw2auth_client_registrations", this.applicationSummaryEntity, (v) -> v.get().clientRegistrations());
        meterRegistry.gauge("gw2auth_client_authorizations", this.applicationSummaryEntity, (v) -> v.get().clientAuthorizations());
    }

    @Override
    public void setClock(Clock clock) {
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public ApplicationSummary getApplicationSummary() {
        final ApplicationSummaryEntity value = this.applicationSummaryEntity.get();

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

    @Scheduled(fixedRate = 5L, timeUnit = TimeUnit.MINUTES)
    public void updateApplicationSummaryCache() {
        this.applicationSummaryEntity.set(this.summaryRepository.getApplicationSummary());
    }
}
