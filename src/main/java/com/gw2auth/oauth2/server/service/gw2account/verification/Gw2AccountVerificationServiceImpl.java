package com.gw2auth.oauth2.server.service.gw2account.verification;

import com.gw2auth.oauth2.server.repository.gw2account.apitoken.Gw2AccountApiTokenRepository;
import com.gw2auth.oauth2.server.repository.gw2account.verification.*;
import com.gw2auth.oauth2.server.service.Clocked;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.gw2.Gw2Account;
import com.gw2auth.oauth2.server.service.gw2.Gw2ApiService;
import com.gw2auth.oauth2.server.service.gw2.Gw2SubToken;
import com.gw2auth.oauth2.server.service.gw2account.Gw2AccountService;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Tags;
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

    private final Gw2AccountApiTokenRepository gw2AccountApiTokenRepository;
    private final Gw2AccountVerificationRepository gw2AccountVerificationRepository;
    private final Gw2AccountVerificationChallengeRepository gw2AccountVerificationChallengeRepository;
    private final Gw2AccountVerificationChallengePendingRepository gw2AccountVerificationChallengePendingRepository;
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
                                             Gw2AccountVerificationChallengePendingRepository gw2AccountVerificationChallengePendingRepository,
                                             Gw2ApiService gw2ApiService,
                                             AccountService accountService,
                                             Gw2AccountService gw2AccountService,
                                             MeterRegistry meterRegistry) {

        this.gw2AccountApiTokenRepository = gw2AccountApiTokenRepository;
        this.gw2AccountVerificationRepository = gw2AccountVerificationRepository;
        this.gw2AccountVerificationChallengeRepository = gw2AccountVerificationChallengeRepository;
        this.gw2AccountVerificationChallengePendingRepository = gw2AccountVerificationChallengePendingRepository;
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
                .collect(Collectors.toUnmodifiableSet());
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
        return this.gw2AccountVerificationChallengeRepository.findByAccountId(accountId)
                .flatMap((entity) -> {
                    final VerificationChallenge<?> verificationChallenge = this.challengesById.get(entity.challengeId());
                    if (verificationChallenge == null) {
                        this.gw2AccountVerificationChallengeRepository.deleteByAccountId(accountId);
                        return Optional.empty();
                    }

                    final Map<String, Object> message;
                    try {
                        message = buildMessage(verificationChallenge, entity.state());
                    } catch (IOException e) {
                        return Optional.empty();
                    }

                    return Optional.of(new VerificationChallengeStart(verificationChallenge.getId(), message, this.clock.instant()));
                });
    }

    @Override
    public List<VerificationChallengePending> getPendingChallenges(UUID accountId) {
        return this.gw2AccountVerificationChallengePendingRepository.findAllByAccountId(accountId).stream()
                .map((e) -> new VerificationChallengePending(e.challengeId(), e.gw2AccountId(), e.submitTime()))
                .collect(Collectors.toList());

    }

    @Override
    @Transactional
    public VerificationChallengeStart startChallenge(UUID accountId, long challengeId) {
        final VerificationChallenge<?> verificationChallenge = this.challengesById.get(challengeId);
        if (verificationChallenge == null) {
            throw new Gw2AccountVerificationServiceException("", HttpStatus.BAD_REQUEST);
        }

        final Optional<Gw2AccountVerificationChallengeEntity> optional = this.gw2AccountVerificationChallengeRepository.findByAccountId(accountId);
        final Instant currentTime = this.clock.instant();

        if (optional.isPresent()) {
            final Gw2AccountVerificationChallengeEntity currentStartedChallenge = optional.get();

            if (currentStartedChallenge.challengeId() == challengeId) {
                throw new Gw2AccountVerificationServiceException(Gw2AccountVerificationServiceException.CHALLENGE_ALREADY_STARTED, HttpStatus.BAD_REQUEST);
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
                new Gw2AccountVerificationChallengeEntity(accountId, challenge.getId(), rawState, currentTime)
        );

        return new VerificationChallengeStart(entity.challengeId(), challenge.buildMessage(state), this.clock.instant());
    }

    @Override
    @Transactional
    public VerificationChallengeSubmit submitChallenge(UUID accountId, String gw2ApiToken) {
        Gw2AccountVerificationChallengeEntity entity = this.gw2AccountVerificationChallengeRepository.findByAccountId(accountId)
                .orElseThrow(() -> new Gw2AccountVerificationServiceException(Gw2AccountVerificationServiceException.CHALLENGE_NOT_FOUND, HttpStatus.NOT_FOUND));

        this.gw2AccountVerificationChallengeRepository.deleteByAccountId(accountId);

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

        final Gw2Account gw2Account = this.gw2ApiService.getAccount(gw2SubToken.value());
        final UUID gw2AccountId = gw2Account.id();
        final Gw2AccountVerificationChallengePendingEntity pendingChallengeEntity = this.gw2AccountVerificationChallengePendingRepository.findByAccountIdAndGw2AccountId(accountId, gw2AccountId).orElse(null);

        if (pendingChallengeEntity != null) {
            // allow only one active challenge per gw2 account
            throw new Gw2AccountVerificationServiceException(Gw2AccountVerificationServiceException.CHALLENGE_FOR_THIS_GW2_ACCOUNT_ALREADY_STARTED, HttpStatus.BAD_REQUEST);
        } else if (Objects.equals(this.gw2AccountVerificationRepository.findByGw2AccountId(gw2AccountId).map(Gw2AccountVerificationEntity::accountId).orElse(null), accountId)) {
            // if this gw2 account is already verified for this same gw2auth account, dont proceed
            throw new Gw2AccountVerificationServiceException(Gw2AccountVerificationServiceException.GW2_ACCOUNT_ALREADY_VERIFIED, HttpStatus.BAD_REQUEST);
        }

        final boolean isVerified;
        final Gw2AccountVerificationChallengePendingEntity pendingEntity;

        try (AccountService.LoggingContext logging = this.accountService.log(accountId, Map.of("type", "gw2.verification.submit", "gw2_account_id", gw2AccountId, "challenge_id", entity.challengeId()))) {
            logging.log("Received submit for GW2 account verification");

            // verifications and challenges are linked to gw2_account, the account entity needs to be created first
            // setting the (GW2Auth) display name of the account entity to its (GW2) display name by default (will be ignored if the entity already exists)
            this.gw2AccountService.getOrCreateGw2Account(accountId, gw2AccountId, gw2Account.name(), gw2Account.name());

            pendingEntity = new Gw2AccountVerificationChallengePendingEntity(
                    entity.accountId(),
                    gw2AccountId,
                    entity.challengeId(),
                    entity.state(),
                    gw2SubToken.value(),
                    entity.creationTime(),
                    startTime,
                    timeout
            );

            isVerified = verify(logging, pendingEntity);
        }

        final VerificationChallengePending verificationChallengePending;
        if (isVerified) {
            verificationChallengePending = null;
        } else {
            this.gw2AccountVerificationChallengePendingRepository.save(pendingEntity);
            verificationChallengePending = new VerificationChallengePending(entity.challengeId(), gw2AccountId, startTime);
        }

        return new VerificationChallengeSubmit(verificationChallengePending, isVerified);
    }

    @Override
    public void cancelPendingChallenge(UUID accountId, UUID gw2AccountId) {
        if (!this.gw2AccountVerificationChallengePendingRepository.deleteByAccountIdAndGw2AccountId(accountId, gw2AccountId)) {
            throw new Gw2AccountVerificationServiceException(Gw2AccountVerificationServiceException.CHALLENGE_NOT_FOUND, HttpStatus.NOT_FOUND);
        }
    }

    @Transactional(noRollbackFor = Gw2AccountVerificationServiceException.class)
    public boolean verify(AccountService.LoggingContext logging, Gw2AccountVerificationChallengePendingEntity entity) {
        final UUID accountId = entity.accountId();
        final UUID gw2AccountId = entity.gw2AccountId();

        final VerificationChallenge<?> challenge = this.challengesById.get(entity.challengeId());
        if (challenge == null) {
            this.gw2AccountVerificationChallengePendingRepository.deleteByAccountIdAndGw2AccountId(accountId, gw2AccountId);
            throw new Gw2AccountVerificationServiceException(Gw2AccountVerificationServiceException.CHALLENGE_NOT_FOUND, HttpStatus.NOT_FOUND);
        }

        final boolean isVerified;
        try {
            isVerified = verify(challenge, entity.state(), entity.gw2ApiToken());
        } catch (IOException e) {
            this.gw2AccountVerificationChallengePendingRepository.deleteByAccountIdAndGw2AccountId(accountId, gw2AccountId);
            throw new Gw2AccountVerificationServiceException(Gw2AccountVerificationServiceException.CHALLENGE_NOT_FOUND, HttpStatus.NOT_FOUND);
        }

        if (isVerified) {
            this.gw2AccountVerificationChallengePendingRepository.deleteByAccountIdAndGw2AccountId(accountId, gw2AccountId);
            this.gw2AccountApiTokenRepository.deleteAllByGw2AccountIdExceptForAccountId(gw2AccountId, accountId);
            this.gw2AccountVerificationRepository.save(new Gw2AccountVerificationEntity(gw2AccountId, accountId));

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
        final List<Gw2AccountVerificationChallengePendingEntity> entities = this.gw2AccountVerificationChallengePendingRepository.findAll();

        if (!entities.isEmpty()) {
            LOG.info("processing {} pending challenges", entities.size());

            for (Gw2AccountVerificationChallengePendingEntity entity : entities) {
                final UUID accountId = entity.accountId();
                final UUID gw2AccountId = entity.gw2AccountId();

                try (AccountService.LoggingContext logging = this.accountService.log(accountId, Map.of("type", "gw2.verification.attempt", "gw2_account_id", gw2AccountId, "challenge_id", entity.challengeId()))) {
                    logging.log("Trying to verify GW2 account");

                    try {
                        if (now.isAfter(entity.timeoutTime())) {
                            this.gw2AccountVerificationChallengePendingRepository.deleteByAccountIdAndGw2AccountId(entity.accountId(), entity.gw2AccountId());
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

    private void recordMetric(Gw2AccountVerificationChallengePendingEntity entity, boolean success) {
        final Instant completionTime = this.clock.instant();
        final Tags tags = Tags.of(
                Tag.of("challenge_id", Long.toString(entity.challengeId())),
                Tag.of("success", Boolean.toString(success))
        );

        this.meterRegistry.timer("gw2auth_challenge_completion_time", tags)
                .record(Duration.between(entity.creationTime(), completionTime));

        this.meterRegistry.timer("gw2auth_challenge_submit_to_completion_time", tags)
                .record(Duration.between(entity.submitTime(), completionTime));
    }

    private <S> Map<String, Object> buildMessage(VerificationChallenge<S> challenge, String rawState) throws IOException {
        return challenge.buildMessage(challenge.readState(rawState));
    }
}
