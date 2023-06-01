package com.gw2auth.oauth2.server.service.gw2account.verification;

import com.gw2auth.oauth2.server.repository.gw2account.apitoken.Gw2AccountApiTokenRepository;
import com.gw2auth.oauth2.server.repository.gw2account.verification.Gw2AccountVerificationChallengeEntity;
import com.gw2auth.oauth2.server.repository.gw2account.verification.Gw2AccountVerificationChallengeRepository;
import com.gw2auth.oauth2.server.repository.gw2account.verification.Gw2AccountVerificationEntity;
import com.gw2auth.oauth2.server.repository.gw2account.verification.Gw2AccountVerificationRepository;
import com.gw2auth.oauth2.server.service.Clocked;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.gw2.Gw2ApiService;
import com.gw2auth.oauth2.server.service.gw2.Gw2SubToken;
import com.gw2auth.oauth2.server.service.gw2account.Gw2AccountService;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Tags;
import io.micrometer.core.instrument.Timer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Service
@EnableScheduling
public class Gw2AccountVerificationServiceImpl implements Gw2AccountVerificationService, Clocked {

    private static final Logger LOG = LoggerFactory.getLogger(Gw2AccountVerificationServiceImpl.class);
    private static final String STARTED_CHALLENGE_GW2_ACCOUNT_ID = "";
    private static final Duration TIME_BETWEEN_UNFINISHED_STARTS = Duration.ofMinutes(30L);

    private final Gw2AccountApiTokenRepository gw2AccountApiTokenRepository;
    private final Gw2AccountVerificationRepository gw2AccountVerificationRepository;
    private final Gw2AccountVerificationChallengeRepository gw2AccountVerificationChallengeRepository;
    private final Gw2ApiService gw2ApiService;
    private final AccountService accountService;
    private final Gw2AccountService gw2AccountService;
    private final Map<Long, VerificationChallenge<?>> challengesById;
    private final MeterRegistry meterRegistry;
    private Clock clock;

    @Autowired
    public Gw2AccountVerificationServiceImpl(Collection<VerificationChallenge<?>> verificationChallenges,
                                             Gw2AccountApiTokenRepository gw2AccountApiTokenRepository,
                                             Gw2AccountVerificationRepository gw2AccountVerificationRepository,
                                             Gw2AccountVerificationChallengeRepository gw2AccountVerificationChallengeRepository,
                                             Gw2ApiService gw2ApiService,
                                             AccountService accountService,
                                             Gw2AccountService gw2AccountService,
                                             MeterRegistry meterRegistry) {

        this.gw2AccountApiTokenRepository = gw2AccountApiTokenRepository;
        this.gw2AccountVerificationRepository = gw2AccountVerificationRepository;
        this.gw2AccountVerificationChallengeRepository = gw2AccountVerificationChallengeRepository;
        this.gw2ApiService = gw2ApiService;
        this.accountService = accountService;
        this.gw2AccountService = gw2AccountService;
        this.meterRegistry = meterRegistry;
        this.clock = Clock.systemDefaultZone();

        final Map<Long, VerificationChallenge<?>> challengesById = new HashMap<>(verificationChallenges.size());

        for (VerificationChallenge<?> verificationChallenge : verificationChallenges) {
            if (challengesById.put(verificationChallenge.getId(), verificationChallenge) != null) {
                throw new IllegalArgumentException("duplicate challenge id: " + verificationChallenge.getId());
            }
        }

        this.challengesById = Map.copyOf(challengesById);
    }

    @Override
    public void setClock(Clock clock) {
        this.clock = clock;
    }

    @Override
    public Set<UUID> getVerifiedGw2AccountIds(UUID accountId) {
        return this.gw2AccountVerificationRepository.findAllByAccountId(accountId).stream()
                .map(Gw2AccountVerificationEntity::gw2AccountId)
                .collect(Collectors.toSet());
    }

    @Override
    public Optional<UUID> getVerifiedAccountId(UUID gw2AccountId) {
        return this.gw2AccountVerificationRepository.findByGw2AccountId(gw2AccountId)
                .map(Gw2AccountVerificationEntity::accountId);
    }

    @Override
    public List<VerificationChallenge<?>> getAvailableChallenges() {
        return List.copyOf(this.challengesById.values());
    }

    @Override
    public Optional<VerificationChallengeStart> getStartedChallenge(UUID accountId) {
        return this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, STARTED_CHALLENGE_GW2_ACCOUNT_ID)
                .flatMap((entity) -> {
                    final VerificationChallenge<?> verificationChallenge = this.challengesById.get(entity.challengeId());
                    if (verificationChallenge == null) {
                        this.gw2AccountVerificationChallengeRepository.deleteByAccountIdAndGw2AccountId(accountId, STARTED_CHALLENGE_GW2_ACCOUNT_ID);
                        return Optional.empty();
                    }

                    final Map<String, Object> message;
                    try {
                        message = buildMessage(verificationChallenge, entity.state());
                    } catch (IOException e) {
                        return Optional.empty();
                    }

                    return Optional.of(new VerificationChallengeStart(verificationChallenge.getId(), message, entity.timeoutAt()));
                });
    }

    @Override
    public List<VerificationChallengePending> getPendingChallenges(UUID accountId) {
        return this.gw2AccountVerificationChallengeRepository.findAllByAccountId(accountId).stream()
                .filter((e) -> !e.gw2AccountId().equals(STARTED_CHALLENGE_GW2_ACCOUNT_ID))
                .map((e) -> new VerificationChallengePending(e.challengeId(), UUID.fromString(e.gw2AccountId()), e.startedAt()))
                .collect(Collectors.toList());

    }

    @Override
    @Transactional
    public VerificationChallengeStart startChallenge(UUID accountId, long challengeId) {
        final VerificationChallenge<?> verificationChallenge = this.challengesById.get(challengeId);
        if (verificationChallenge == null) {
            throw new Gw2AccountVerificationServiceException("", HttpStatus.BAD_REQUEST);
        }

        final Optional<Gw2AccountVerificationChallengeEntity> optional = this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, STARTED_CHALLENGE_GW2_ACCOUNT_ID);
        final Instant currentTime = this.clock.instant();

        if (optional.isPresent()) {
            final Gw2AccountVerificationChallengeEntity currentStartedChallenge = optional.get();

            if (currentStartedChallenge.challengeId() == challengeId) {
                throw new Gw2AccountVerificationServiceException(Gw2AccountVerificationServiceException.CHALLENGE_ALREADY_STARTED, HttpStatus.BAD_REQUEST);
            } else if (currentTime.isBefore(currentStartedChallenge.timeoutAt())) {
                throw new Gw2AccountVerificationServiceException(Gw2AccountVerificationServiceException.CHALLENGE_START_NOT_YET_POSSIBLE, HttpStatus.BAD_REQUEST);
            }
        }

        return startChallenge(accountId, currentTime, verificationChallenge);
    }

    private <S> VerificationChallengeStart startChallenge(UUID accountId, Instant currentTime, VerificationChallenge<S> challenge) {
        final S state = challenge.start();

        final String rawState;
        try {
            rawState = challenge.writeState(state);
        } catch (IOException e) {
            throw new Gw2AccountVerificationServiceException(Gw2AccountVerificationServiceException.INTERNAL_SERVER_ERROR, HttpStatus.INTERNAL_SERVER_ERROR);
        }

        final Gw2AccountVerificationChallengeEntity entity = this.gw2AccountVerificationChallengeRepository.save(
                // the timeoutAt in the case of started challenge is not an actual timeout, but the time when a new challenge may be started
                new Gw2AccountVerificationChallengeEntity(accountId, STARTED_CHALLENGE_GW2_ACCOUNT_ID, challenge.getId(), rawState, null, currentTime, currentTime.plus(TIME_BETWEEN_UNFINISHED_STARTS))
        );

        return new VerificationChallengeStart(entity.challengeId(), challenge.buildMessage(state), entity.timeoutAt());
    }

    @Override
    @Transactional
    public VerificationChallengeSubmit submitChallenge(UUID accountId, String gw2ApiToken) {
        Gw2AccountVerificationChallengeEntity entity = this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, STARTED_CHALLENGE_GW2_ACCOUNT_ID)
                .orElseThrow(() -> new Gw2AccountVerificationServiceException(Gw2AccountVerificationServiceException.CHALLENGE_NOT_FOUND, HttpStatus.NOT_FOUND));

        this.gw2AccountVerificationChallengeRepository.deleteByAccountIdAndGw2AccountId(accountId, STARTED_CHALLENGE_GW2_ACCOUNT_ID);

        final VerificationChallenge<?> challenge = this.challengesById.get(entity.challengeId());
        if (challenge == null) {
            throw new Gw2AccountVerificationServiceException(Gw2AccountVerificationServiceException.CHALLENGE_NOT_FOUND, HttpStatus.NOT_FOUND);
        }

        final Instant startTime = this.clock.instant();
        final Instant timeout = startTime.plus(challenge.getTimeout());
        final Gw2SubToken gw2SubToken = this.gw2ApiService.createSubToken(gw2ApiToken, challenge.getRequiredGw2ApiPermissions(), timeout);

        if (!gw2SubToken.permissions().containsAll(challenge.getRequiredGw2ApiPermissions())) {
            throw new Gw2AccountVerificationServiceException(Gw2AccountVerificationServiceException.INSUFFICIENT_PERMISSIONS, HttpStatus.BAD_REQUEST);
        }

        final UUID gw2AccountId = this.gw2ApiService.getAccount(gw2SubToken.value()).id();
        final Gw2AccountVerificationChallengeEntity pendingChallengeEntity = this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, gw2AccountId.toString()).orElse(null);

        if (pendingChallengeEntity != null) {
            // allow only one active challenge per gw2 account
            throw new Gw2AccountVerificationServiceException(Gw2AccountVerificationServiceException.CHALLENGE_FOR_THIS_GW2_ACCOUNT_ALREADY_STARTED, HttpStatus.BAD_REQUEST);
        } else if (Objects.equals(this.gw2AccountVerificationRepository.findByGw2AccountId(gw2AccountId).map(Gw2AccountVerificationEntity::accountId).orElse(null), accountId)) {
            // if this gw2 account is already verified for this same gw2auth account, dont proceed
            throw new Gw2AccountVerificationServiceException(Gw2AccountVerificationServiceException.GW2_ACCOUNT_ALREADY_VERIFIED, HttpStatus.BAD_REQUEST);
        }

        final boolean isVerified;
        try (AccountService.LoggingContext logging = this.accountService.log(accountId, Map.of("type", "gw2.verification.submit", "gw2_account_id", gw2AccountId, "challenge_id", entity.challengeId()))) {
            logging.log("Received submit for GW2 account verification");

            entity = new Gw2AccountVerificationChallengeEntity(
                    entity.accountId(),
                    gw2AccountId.toString(),
                    entity.challengeId(),
                    entity.state(),
                    gw2SubToken.value(),
                    startTime,
                    timeout
            );

            isVerified = verify(logging, entity);
        }

        final VerificationChallengePending verificationChallengePending;
        if (isVerified) {
            verificationChallengePending = null;
        } else {
            this.gw2AccountVerificationChallengeRepository.save(entity);
            verificationChallengePending = new VerificationChallengePending(entity.challengeId(), gw2AccountId, startTime);
        }

        return new VerificationChallengeSubmit(verificationChallengePending, isVerified);
    }

    @Override
    public void cancelPendingChallenge(UUID accountId, UUID gw2AccountId) {
        if (!this.gw2AccountVerificationChallengeRepository.deleteByAccountIdAndGw2AccountId(accountId, gw2AccountId.toString())) {
            throw new Gw2AccountVerificationServiceException(Gw2AccountVerificationServiceException.CHALLENGE_NOT_FOUND, HttpStatus.NOT_FOUND);
        }
    }

    @Transactional(noRollbackFor = Gw2AccountVerificationServiceException.class)
    public boolean verify(AccountService.LoggingContext logging, Gw2AccountVerificationChallengeEntity entity) {
        final UUID accountId = entity.accountId();
        final String gw2AccountId = entity.gw2AccountId();

        final VerificationChallenge<?> challenge = this.challengesById.get(entity.challengeId());
        if (challenge == null) {
            this.gw2AccountVerificationChallengeRepository.deleteByAccountIdAndGw2AccountId(accountId, gw2AccountId);
            throw new Gw2AccountVerificationServiceException(Gw2AccountVerificationServiceException.CHALLENGE_NOT_FOUND, HttpStatus.NOT_FOUND);
        }

        final boolean isVerified;
        try {
            isVerified = verify(challenge, entity.state(), entity.gw2ApiToken());
        } catch (IOException e) {
            this.gw2AccountVerificationChallengeRepository.deleteByAccountIdAndGw2AccountId(accountId, gw2AccountId);
            throw new Gw2AccountVerificationServiceException(Gw2AccountVerificationServiceException.CHALLENGE_NOT_FOUND, HttpStatus.NOT_FOUND);
        }

        if (isVerified) {
            this.gw2AccountVerificationChallengeRepository.deleteByAccountIdAndGw2AccountId(accountId, gw2AccountId);

            final UUID gw2AccountIdUUID = UUID.fromString(gw2AccountId);

            this.gw2AccountApiTokenRepository.deleteAllByGw2AccountIdExceptForAccountId(gw2AccountIdUUID, accountId);
            this.gw2AccountService.getOrCreateGw2Account(
                    accountId,
                    gw2AccountIdUUID,
                    gw2AccountId
            );
            this.gw2AccountVerificationRepository.save(new Gw2AccountVerificationEntity(gw2AccountIdUUID, accountId));

            logging.log("GW2 account verification succeeded!");
            recordMetric(entity, true);
        } else {
            logging.log("GW2 account verification could not be verified yet");
        }

        return isVerified;
    }

    private <S> boolean verify(VerificationChallenge<S> challenge, String rawState, String gw2ApiToken) throws IOException {
        return challenge.verify(challenge.readState(rawState), gw2ApiToken);
    }

    @Scheduled(fixedRate = 60L, timeUnit = TimeUnit.SECONDS)
    public void tryVerifyAllPending() {
        final Instant now = this.clock.instant();
        final List<Gw2AccountVerificationChallengeEntity> entities = this.gw2AccountVerificationChallengeRepository.findAllPending();

        if (!entities.isEmpty()) {
            LOG.info("processing {} pending challenges", entities.size());

            for (Gw2AccountVerificationChallengeEntity entity : entities) {
                final UUID accountId = entity.accountId();
                final String gw2AccountId = entity.gw2AccountId();

                try (AccountService.LoggingContext logging = this.accountService.log(accountId, Map.of("type", "gw2.verification.attempt", "gw2_account_id", gw2AccountId, "challenge_id", entity.challengeId()))) {
                    logging.log("Trying to verify GW2 account");

                    try {
                        if (now.isAfter(entity.timeoutAt())) {
                            this.gw2AccountVerificationChallengeRepository.deleteByAccountIdAndGw2AccountId(entity.accountId(), entity.gw2AccountId());
                            logging.log("GW2 account failed to verify within the allowed period.");
                            recordMetric(entity, false);
                        } else {
                            verify(logging, entity);
                        }
                    } catch (Exception e) {
                        LOG.warn("unexpected exception during verification of challenge", e);
                    }
                }
            }
        }
    }

    private void recordMetric(Gw2AccountVerificationChallengeEntity entity, boolean success) {
        final Timer timer = this.meterRegistry.timer(
                "gw2auth_challenge_completion_time",
                Tags.of(
                        Tag.of("challenge_id", Long.toString(entity.challengeId())),
                        Tag.of("success", Boolean.toString(success))
                )
        );

        timer.record(Duration.between(entity.startedAt(), this.clock.instant()));
    }

    private <S> Map<String, Object> buildMessage(VerificationChallenge<S> challenge, String rawState) throws IOException {
        return challenge.buildMessage(challenge.readState(rawState));
    }
}
