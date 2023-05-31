package com.gw2auth.oauth2.server.service.gw2account.apitoken;

import com.gw2auth.oauth2.server.repository.gw2account.apitoken.Gw2AccountApiTokenEntity;
import com.gw2auth.oauth2.server.repository.gw2account.apitoken.Gw2AccountApiTokenRepository;
import com.gw2auth.oauth2.server.repository.gw2account.apitoken.Gw2AccountApiTokenValidUpdateEntity;
import com.gw2auth.oauth2.server.service.Clocked;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.gw2.*;
import com.gw2auth.oauth2.server.service.gw2account.Gw2AccountService;
import com.gw2auth.oauth2.server.service.gw2account.verification.Gw2AccountVerificationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Service
@EnableScheduling
public class Gw2AccountApiTokenServiceImpl implements Gw2AccountApiTokenService, Clocked {

    private static final Logger LOG = LoggerFactory.getLogger(Gw2AccountApiTokenServiceImpl.class);
    private static final Duration VALIDITY_CHECK_INTERVAL = Duration.ofMinutes(45L);
    private static final Duration IGNORE_TOKENS_INVALID_FOR_LONGER_THAN = Duration.ofDays(7L);
    private static final int VALIDITY_CHECK_BATCH_SIZE = 50;

    private final Gw2AccountApiTokenRepository gw2AccountApiTokenRepository;
    private final AccountService accountService;
    private final Gw2AccountService gw2AccountService;
    private final Gw2AccountVerificationService gw2AccountVerificationService;
    private final Gw2ApiService gw2ApiService;
    private Clock clock;

    public Gw2AccountApiTokenServiceImpl(Gw2AccountApiTokenRepository gw2AccountApiTokenRepository,
                                         AccountService accountService,
                                         Gw2AccountService gw2AccountService,
                                         Gw2AccountVerificationService gw2AccountVerificationService,
                                         Gw2ApiService gw2ApiService) {

        this.gw2AccountApiTokenRepository = gw2AccountApiTokenRepository;
        this.accountService = accountService;
        this.gw2AccountService = gw2AccountService;
        this.gw2AccountVerificationService = gw2AccountVerificationService;
        this.gw2ApiService = gw2ApiService;
        this.clock = Clock.systemUTC();
    }

    @Override
    public void setClock(Clock clock) {
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public List<Gw2AccountApiToken> getApiTokens(UUID accountId) {
        return this.gw2AccountApiTokenRepository.findAllWithPreferencesByAccountId(accountId).stream()
                .map(Gw2AccountApiToken::fromEntity)
                .toList();
    }

    @Override
    public Optional<Gw2AccountApiToken> getApiToken(UUID accountId, UUID gw2AccountId) {
        return this.gw2AccountApiTokenRepository.findWithPreferencesByAccountIdAndGw2AccountId(accountId, gw2AccountId)
                .map(Gw2AccountApiToken::fromEntity);
    }

    @Override
    public List<Gw2AccountApiToken> getApiTokens(UUID accountId, Collection<UUID> gw2AccountIds) {
        return this.gw2AccountApiTokenRepository.findAllWithPreferencesByAccountIdAndGw2AccountIds(accountId, gw2AccountIds).stream()
                .map(Gw2AccountApiToken::fromEntity)
                .toList();
    }

    @Override
    @Transactional(noRollbackFor = Gw2AccountApiTokenOwnershipMismatchException.class)
    public Gw2AccountApiToken addOrUpdateApiToken(UUID accountId, String gw2ApiToken) {
        final Gw2TokenInfo gw2TokenInfo = this.gw2ApiService.getTokenInfo(gw2ApiToken);

        if (!gw2TokenInfo.permissions().contains(Gw2ApiPermission.ACCOUNT)) {
            throw new Gw2AccountApiTokenServiceException(Gw2AccountApiTokenServiceException.MISSING_ACCOUNT_PERMISSION, HttpStatus.BAD_REQUEST);
        }

        final Gw2Account gw2Account = this.gw2ApiService.getAccount(gw2ApiToken);
        final Optional<UUID> optionalVerification = this.gw2AccountVerificationService.getVerifiedAccountId(gw2Account.id());

        if (optionalVerification.isPresent() && !optionalVerification.get().equals(accountId)) {
            this.gw2AccountApiTokenRepository.deleteByAccountIdAndGw2AccountId(accountId, gw2Account.id());
            throw new Gw2AccountApiTokenOwnershipMismatchException();
        }

        final Instant now = this.clock.instant();
        final com.gw2auth.oauth2.server.service.gw2account.Gw2Account gw2AccountBO = this.gw2AccountService.getOrCreateGw2Account(
                accountId,
                gw2Account.id(),
                gw2Account.name()
        );
        final Gw2AccountApiTokenEntity tokenEntity = this.gw2AccountApiTokenRepository.save(new Gw2AccountApiTokenEntity(
                accountId,
                gw2Account.id(),
                now,
                gw2ApiToken,
                Gw2ApiPermission.toBitSet(gw2TokenInfo.permissions()),
                now,
                now
        ));

        this.accountService.log(
                accountId,
                "The API Token has been added or updated",
                Map.of("gw2_account_id", gw2Account.id())
        );

        return Gw2AccountApiToken.fromEntity(tokenEntity, gw2AccountBO.displayName(), gw2AccountBO.orderRank());
    }

    @Override
    @Transactional
    public void deleteApiToken(UUID accountId, UUID gw2AccountId) {
        if (!this.gw2AccountApiTokenRepository.deleteByAccountIdAndGw2AccountId(accountId, gw2AccountId)) {
            throw new Gw2AccountApiTokenServiceException(Gw2AccountApiTokenServiceException.API_TOKEN_NOT_FOUND, HttpStatus.NOT_FOUND);
        }

        this.accountService.log(
                accountId,
                "The API Token has been deleted",
                Map.of("gw2_account_id", gw2AccountId)
        );
    }

    @Override
    public void updateApiTokensValid(Instant lastValidCheckTime, Collection<Gw2AccountApiTokenValidUpdate> _updates) {
        final List<Gw2AccountApiTokenValidUpdateEntity> updates = _updates.stream()
                .map((v) -> new Gw2AccountApiTokenValidUpdateEntity(v.accountId(), v.gw2AccountId(), v.isValid()))
                .toList();

        this.gw2AccountApiTokenRepository.updateApiTokensValid(lastValidCheckTime, updates);
    }

    @Scheduled(fixedRate = 10L, timeUnit = TimeUnit.MINUTES)
    public void checkTokenValidity() {
        final Instant now = this.clock.instant();
        final List<Gw2AccountApiTokenEntity> tokensToCheck = this.gw2AccountApiTokenRepository.findAllByLastValidTimeGTEAndLastValidCheckTimeLTE(
                now.minus(IGNORE_TOKENS_INVALID_FOR_LONGER_THAN),
                now.minus(VALIDITY_CHECK_INTERVAL),
                VALIDITY_CHECK_BATCH_SIZE
        );
        final List<Gw2AccountApiTokenValidUpdateEntity> updateEntities = new ArrayList<>(tokensToCheck.size());
        final int[] counts = new int[3];

        for (Gw2AccountApiTokenEntity apiTokenEntity : tokensToCheck) {
            Boolean isValidState;
            try {
                this.gw2ApiService.getTokenInfo(apiTokenEntity.gw2ApiToken());
                isValidState = true;
                counts[0]++;
            } catch (InvalidApiTokenException e) {
                isValidState = false;
                counts[1]++;
            } catch (Gw2ApiServiceException e) {
                isValidState = null;
                counts[2]++;
            }

            if (isValidState != null) {
                updateEntities.add(new Gw2AccountApiTokenValidUpdateEntity(apiTokenEntity.accountId(), apiTokenEntity.gw2AccountId(), isValidState));
            }
        }

        if (!updateEntities.isEmpty()) {
            this.gw2AccountApiTokenRepository.updateApiTokensValid(now, updateEntities);
            LOG.info("updated API-Token validity for {} API-Tokens; valid={} invalid={} unknown={}", tokensToCheck.size(), counts[0], counts[1], counts[2]);
        }
    }
}
