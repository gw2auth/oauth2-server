package com.gw2auth.oauth2.server.service.summary;

import com.gw2auth.oauth2.server.repository.summary.ApplicationSummaryEntity;
import com.gw2auth.oauth2.server.repository.summary.SummaryRepository;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

@Service
public class SummaryServiceImpl implements SummaryService {

    private final SummaryRepository summaryRepository;
    private final AtomicReference<ApplicationSummaryEntity> applicationSummaryEntity;

    @Autowired
    public SummaryServiceImpl(SummaryRepository summaryRepository, MeterRegistry meterRegistry) {
        this.summaryRepository = summaryRepository;
        this.applicationSummaryEntity = new AtomicReference<>(this.summaryRepository.getApplicationSummary());

        meterRegistry.gauge("gw2auth_registered_accounts", this.applicationSummaryEntity, (v) -> v.get().accounts());
        meterRegistry.gauge("gw2auth_api_tokens", this.applicationSummaryEntity, (v) -> v.get().apiTokens());
        meterRegistry.gauge("gw2auth_verified_gw2_accounts", this.applicationSummaryEntity, (v) -> v.get().verifiedGw2Accounts());
        meterRegistry.gauge("gw2auth_client_registrations", this.applicationSummaryEntity, (v) -> v.get().clientRegistrations());
        meterRegistry.gauge("gw2auth_client_authorizations", this.applicationSummaryEntity, (v) -> v.get().clientAuthorizations());
    }

    @Scheduled(fixedRate = 5L, timeUnit = TimeUnit.MINUTES)
    public void updateApplicationSummaryCache() {
        this.applicationSummaryEntity.set(this.summaryRepository.getApplicationSummary());
    }
}
