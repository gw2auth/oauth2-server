package com.gw2auth.oauth2.server.service.verification;

import com.gw2auth.oauth2.server.repository.apitoken.ApiTokenRepository;
import com.gw2auth.oauth2.server.repository.verification.Gw2AccountVerificationChallengeEntity;
import com.gw2auth.oauth2.server.repository.verification.Gw2AccountVerificationChallengeRepository;
import com.gw2auth.oauth2.server.repository.verification.Gw2AccountVerificationEntity;
import com.gw2auth.oauth2.server.repository.verification.Gw2AccountVerificationRepository;
import com.gw2auth.oauth2.server.service.gw2.Gw2ApiService;
import com.gw2auth.oauth2.server.service.gw2.Gw2SubToken;
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
import java.util.stream.Collectors;

@Service
@EnableScheduling
public class VerificationServiceImpl implements VerificationService {

    private static final Logger LOG = LoggerFactory.getLogger(VerificationServiceImpl.class);
    private static final String STARTED_CHALLENGE_GW2_ACCOUNT_ID = "";
    private static final Duration TIME_BETWEEN_UNFINISHED_STARTS = Duration.ofMinutes(30L);
    private static final long VERIFICATION_FAILED_CHALLENGE_ID = -1L;
    private static final Duration VERIFICATION_FAILED_BLOCK_DURATION = Duration.ofHours(2L);

    private final Gw2AccountVerificationRepository gw2AccountVerificationRepository;
    private final Gw2AccountVerificationChallengeRepository gw2AccountVerificationChallengeRepository;
    private final ApiTokenRepository apiTokenRepository;
    private final Gw2ApiService gw2ApiService;
    private final Map<Long, VerificationChallenge<?>> challengesById;
    private volatile Clock clock;

    @Autowired
    public VerificationServiceImpl(Collection<VerificationChallenge<?>> verificationChallenges, Gw2AccountVerificationRepository gw2AccountVerificationRepository, Gw2AccountVerificationChallengeRepository gw2AccountVerificationChallengeRepository, ApiTokenRepository apiTokenRepository, Gw2ApiService gw2ApiService) {
        this.gw2AccountVerificationRepository = gw2AccountVerificationRepository;
        this.gw2AccountVerificationChallengeRepository = gw2AccountVerificationChallengeRepository;
        this.apiTokenRepository = apiTokenRepository;
        this.gw2ApiService = gw2ApiService;
        this.clock = Clock.systemDefaultZone();

        final Map<Long, VerificationChallenge<?>> challengesById = new HashMap<>(verificationChallenges.size());

        for (VerificationChallenge<?> verificationChallenge : verificationChallenges) {
            if (challengesById.put(verificationChallenge.getId(), verificationChallenge) != null) {
                throw new IllegalArgumentException("duplicate challenge id: " + verificationChallenge.getId());
            }
        }

        this.challengesById = Map.copyOf(challengesById);
    }

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
                .filter((e) -> e.challengeId() != VERIFICATION_FAILED_CHALLENGE_ID)
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
            if (pendingChallengeEntity.challengeId() == VERIFICATION_FAILED_CHALLENGE_ID) {
                final Duration timeUntilAvailable = Duration.between(this.clock.instant(), pendingChallengeEntity.timeoutAt());
                final long minutes = timeUntilAvailable.toMinutes();

                // a verification for this gw2-account failed before
                throw new Gw2AccountVerificationServiceException(String.format(Gw2AccountVerificationServiceException.CHALLENGE_FOR_THIS_ACCOUNT_BLOCKED, minutes), HttpStatus.BAD_REQUEST);
            } else {
                // allow only one active challenge per gw2 account
                throw new Gw2AccountVerificationServiceException(Gw2AccountVerificationServiceException.CHALLENGE_FOR_THIS_GW2_ACCOUNT_ALREADY_STARTED, HttpStatus.BAD_REQUEST);
            }
        } else if (Objects.equals(this.gw2AccountVerificationRepository.findByGw2AccountId(gw2AccountId).map(Gw2AccountVerificationEntity::accountId).orElse(null), accountId)) {
            // if this gw2 account is already verified for this same gw2auth account, dont proceed
            throw new Gw2AccountVerificationServiceException(Gw2AccountVerificationServiceException.GW2_ACCOUNT_ALREADY_VERIFIED, HttpStatus.BAD_REQUEST);
        }

        entity = new Gw2AccountVerificationChallengeEntity(
                entity.accountId(),
                gw2AccountId.toString(),
                entity.challengeId(),
                entity.state(),
                gw2SubToken.value(),
                startTime,
                timeout
        );

        final boolean isVerified = verify(entity);
        final VerificationChallengePending verificationChallengePending;

        if (isVerified) {
            verificationChallengePending = null;
        } else {
            this.gw2AccountVerificationChallengeRepository.save(entity);
            verificationChallengePending = new VerificationChallengePending(entity.challengeId(), gw2AccountId, startTime);
        }

        return new VerificationChallengeSubmit(verificationChallengePending, isVerified);
    }

    @Transactional(noRollbackFor = Gw2AccountVerificationServiceException.class)
    protected boolean verify(Gw2AccountVerificationChallengeEntity entity) {
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

            this.apiTokenRepository.deleteAllByGw2AccountIdExceptForAccountId(gw2AccountIdUUID, accountId);
            this.gw2AccountVerificationRepository.save(
                    this.gw2AccountVerificationRepository.findByGw2AccountId(gw2AccountIdUUID)
                            .map((e) -> e.withAccountId(accountId))
                            .orElseGet(() -> new Gw2AccountVerificationEntity(gw2AccountIdUUID, accountId))
            );
        }

        return isVerified;
    }

    private <S> boolean verify(VerificationChallenge<S> challenge, String rawState, String gw2ApiToken) throws IOException {
        return challenge.verify(challenge.readState(rawState), gw2ApiToken);
    }

    @Scheduled(fixedRate = 1000L * 60L)
    public void tryVerifyAllPending() {
        final Instant now = this.clock.instant();
        final List<Gw2AccountVerificationChallengeEntity> entities = this.gw2AccountVerificationChallengeRepository.findAllPending();

        if (!entities.isEmpty()) {
            LOG.info("processing {} pending challenges", entities.size());

            for (Gw2AccountVerificationChallengeEntity entity : entities) {
                final boolean isExpired = now.isAfter(entity.timeoutAt());
                final boolean isVerificationFailedChallenge = entity.challengeId() == VERIFICATION_FAILED_CHALLENGE_ID;

                try {
                    if (isExpired) {
                        if (isVerificationFailedChallenge) {
                            this.gw2AccountVerificationChallengeRepository.deleteByAccountIdAndGw2AccountId(entity.accountId(), entity.gw2AccountId());
                        } else {
                            this.gw2AccountVerificationChallengeRepository.save(new Gw2AccountVerificationChallengeEntity(
                                    entity.accountId(),
                                    entity.gw2AccountId(),
                                    VERIFICATION_FAILED_CHALLENGE_ID,
                                    null,
                                    null,
                                    now,
                                    now.plus(VERIFICATION_FAILED_BLOCK_DURATION)
                            ));
                        }
                    } else {
                        if (!isVerificationFailedChallenge) {
                            verify(entity);
                        }
                    }
                } catch (Exception e) {
                    LOG.warn("unexpected exception during verification of challenge", e);
                }
            }
        }
    }

    private <S> Map<String, Object> buildMessage(VerificationChallenge<S> challenge, String rawState) throws IOException {
        return challenge.buildMessage(challenge.readState(rawState));
    }
}
