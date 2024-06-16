package com.gw2auth.oauth2.server.service.gw2account.apitoken;

import com.gw2auth.oauth2.server.repository.gw2account.Gw2AccountNameUpdateEntity;
import com.gw2auth.oauth2.server.repository.gw2account.Gw2AccountRepository;
import com.gw2auth.oauth2.server.repository.gw2account.apitoken.Gw2AccountApiTokenRepository;
import com.gw2auth.oauth2.server.repository.gw2account.apitoken.Gw2AccountRefreshEntity;
import com.gw2auth.oauth2.server.repository.gw2account.apitoken.Gw2AccountApiTokenValidUpdateEntity;
import com.gw2auth.oauth2.server.service.Clocked;
import com.gw2auth.oauth2.server.service.gw2.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Service
@EnableScheduling
public class Gw2AccountApiTokenServiceImpl implements Gw2AccountApiTokenService, Clocked {

    private static final Logger LOG = LoggerFactory.getLogger(Gw2AccountApiTokenServiceImpl.class);
    private static final int VALIDITY_CHECK_BATCH_SIZE = 50;

    private final Duration nameCheckInterval;
    private final Duration validCheckInterval;
    private final Duration validCheckIgnoreAfter;
    private final Gw2AccountRepository gw2AccountRepository;
    private final Gw2AccountApiTokenRepository gw2AccountApiTokenRepository;
    private final Gw2ApiService gw2ApiService;
    private Clock clock;

    public Gw2AccountApiTokenServiceImpl(@Value("${com.gw2auth.token.name-check.interval}") Duration nameCheckInterval,
                                         @Value("${com.gw2auth.token.valid-check.interval}") Duration validCheckInterval,
                                         @Value("${com.gw2auth.token.valid-check.ignore-after}") Duration validCheckIgnoreAfter,
                                         Gw2AccountRepository gw2AccountRepository,
                                         Gw2AccountApiTokenRepository gw2AccountApiTokenRepository,
                                         Gw2ApiService gw2ApiService) {

        this.validCheckInterval = validCheckInterval;
        this.validCheckIgnoreAfter = validCheckIgnoreAfter;
        this.nameCheckInterval = nameCheckInterval;
        this.gw2AccountRepository = gw2AccountRepository;
        this.gw2AccountApiTokenRepository = gw2AccountApiTokenRepository;
        this.gw2ApiService = gw2ApiService;
        this.clock = Clock.systemUTC();
    }

    @Override
    public void setClock(Clock clock) {
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public void updateApiTokensValid(Instant lastValidCheckTime, Collection<Gw2AccountApiTokenValidUpdate> _updates) {
        final List<Gw2AccountApiTokenValidUpdateEntity> updates = _updates.stream()
                .map((v) -> new Gw2AccountApiTokenValidUpdateEntity(v.accountId(), v.gw2AccountId(), v.isValid()))
                .toList();

        this.gw2AccountApiTokenRepository.updateApiTokensValid(lastValidCheckTime, updates);
    }

    @Scheduled(fixedRate = 10L, timeUnit = TimeUnit.MINUTES)
    public void refreshTokenValidityAndAccountName() {
        final Instant now = this.clock.instant();
        final List<Gw2AccountRefreshEntity> tokensToCheck = this.gw2AccountApiTokenRepository.findAllApplicableForRefresh(
                now.minus(this.validCheckIgnoreAfter),
                now.minus(this.validCheckInterval),
                now.minus(this.nameCheckInterval),
                VALIDITY_CHECK_BATCH_SIZE
        );
        final List<Gw2AccountApiTokenValidUpdateEntity> validUpdateEntities = new ArrayList<>(tokensToCheck.size());
        final List<Gw2AccountNameUpdateEntity> nameUpdateEntities = new ArrayList<>(tokensToCheck.size());
        int validCount = 0;
        int invalidCount = 0;
        int unknownCount = 0;
        int accountNameChangedCount = 0;

        for (Gw2AccountRefreshEntity apiTokenValidCheckEntity : tokensToCheck) {
            Boolean isValidState;
            try {
                final Gw2Account gw2Account = this.gw2ApiService.getAccount(apiTokenValidCheckEntity.gw2ApiToken());
                isValidState = true;
                validCount++;

                final boolean hasAccountNameChanged = !gw2Account.name().equals(apiTokenValidCheckEntity.gw2AccountName());
                nameUpdateEntities.add(new Gw2AccountNameUpdateEntity(apiTokenValidCheckEntity.accountId(), apiTokenValidCheckEntity.gw2AccountId(), gw2Account.name(), hasAccountNameChanged));

                if (hasAccountNameChanged) {
                    LOG.info(
                            "gw2 account name changed for gw2_account_id={} on account_id={}; old={} new={}",
                            apiTokenValidCheckEntity.gw2AccountId(),
                            apiTokenValidCheckEntity.accountId(),
                            apiTokenValidCheckEntity.gw2AccountName(),
                            gw2Account.name()
                    );
                    accountNameChangedCount++;
                }
            } catch (InvalidApiTokenException e) {
                isValidState = false;
                invalidCount++;
            } catch (Gw2ApiServiceException e) {
                isValidState = null;
                unknownCount++;
            }

            if (isValidState != null) {
                validUpdateEntities.add(new Gw2AccountApiTokenValidUpdateEntity(apiTokenValidCheckEntity.accountId(), apiTokenValidCheckEntity.gw2AccountId(), isValidState));
            }
        }

        if (!validUpdateEntities.isEmpty()) {
            this.gw2AccountApiTokenRepository.updateApiTokensValid(now, validUpdateEntities);
            LOG.info("updated api token validity for {} api tokens; valid={} invalid={} unknown={}", tokensToCheck.size(), validCount, invalidCount, unknownCount);
        }

        if (!nameUpdateEntities.isEmpty()) {
            this.gw2AccountRepository.updateGw2AccountNames(now, nameUpdateEntities);
            LOG.info("updated gw2 account names for {} accounts", accountNameChangedCount);
        }
    }
}
