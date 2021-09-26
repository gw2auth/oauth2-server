package com.gw2auth.oauth2.server.service.verification;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gw2auth.oauth2.server.repository.verification.Gw2AccountVerificationChallengeEntity;
import com.gw2auth.oauth2.server.repository.verification.Gw2AccountVerificationChallengeRepository;
import com.gw2auth.oauth2.server.repository.verification.Gw2AccountVerificationEntity;
import com.gw2auth.oauth2.server.repository.verification.Gw2AccountVerificationRepository;
import com.gw2auth.oauth2.server.service.gw2.Gw2ApiService;
import com.gw2auth.oauth2.server.service.gw2.Gw2SubToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class VerificationServiceImpl implements VerificationService {

    private static final Logger LOG = LoggerFactory.getLogger(VerificationServiceImpl.class);

    private final Gw2AccountVerificationRepository gw2AccountVerificationRepository;
    private final Gw2AccountVerificationChallengeRepository gw2AccountVerificationChallengeRepository;
    private final Gw2ApiService gw2ApiService;
    private final ObjectMapper objectMapper;
    private final Map<Long, VerificationChallenge<?>> challengesById;

    @Autowired
    public VerificationServiceImpl(Collection<VerificationChallenge<?>> verificationChallenges, Gw2AccountVerificationRepository gw2AccountVerificationRepository, Gw2AccountVerificationChallengeRepository gw2AccountVerificationChallengeRepository, Gw2ApiService gw2ApiService, ObjectMapper objectMapper) {
        this.gw2AccountVerificationRepository = gw2AccountVerificationRepository;
        this.gw2AccountVerificationChallengeRepository = gw2AccountVerificationChallengeRepository;
        this.gw2ApiService = gw2ApiService;
        this.objectMapper = objectMapper;

        final Map<Long, VerificationChallenge<?>> challengesById = new HashMap<>(verificationChallenges.size());

        for (VerificationChallenge<?> verificationChallenge : verificationChallenges) {
            if (challengesById.put(verificationChallenge.getId(), verificationChallenge) != null) {
                throw new IllegalArgumentException("duplicate challenge id: " + verificationChallenge.getId());
            }
        }

        this.challengesById = Map.copyOf(challengesById);
    }

    @Override
    public Set<String> getVerifiedGw2AccountIds(long accountId) {
        return this.gw2AccountVerificationRepository.findAllByAccountId(accountId).stream()
                .map(Gw2AccountVerificationEntity::gw2AccountId)
                .collect(Collectors.toSet());
    }

    @Override
    public OptionalLong getVerifiedAccountId(String gw2AccountId) {
        return this.gw2AccountVerificationRepository.findById(gw2AccountId)
                .map(Gw2AccountVerificationEntity::accountId)
                .map(OptionalLong::of)
                .orElse(OptionalLong.empty());
    }

    @Override
    public List<VerificationChallenge<?>> getAvailableChallenges() {
        return List.copyOf(this.challengesById.values());
    }

    @Override
    public Optional<VerificationChallengeStart> getStartedChallenge(long accountId) {
        final Locale userLocale = LocaleContextHolder.getLocale();

        return this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, "")
                .flatMap((entity) -> {
                    final VerificationChallenge<?> verificationChallenge = this.challengesById.get(entity.challengeId());
                    if (verificationChallenge == null) {
                        this.gw2AccountVerificationChallengeRepository.deleteByAccountIdAndGw2AccountId(accountId, "");
                        return Optional.empty();
                    }

                    return deserialize(entity.stateClass(), entity.state())
                            .map((state) -> buildMessage(verificationChallenge, state, userLocale))
                            .map((msg) -> new VerificationChallengeStart(entity.challengeId(), msg));
                });
    }

    @Override
    public List<VerificationChallengePending> getPendingChallenges(long accountId) {
        return this.gw2AccountVerificationChallengeRepository.findAllByAccountId(accountId).stream()
                .filter((e) -> !e.gw2AccountId().equals(""))
                .map((e) -> new VerificationChallengePending(e.challengeId(), e.gw2AccountId(), e.startedAt()))
                .collect(Collectors.toList());

    }

    @Override
    public VerificationChallengeStart startChallenge(long accountId, long challengeId) {
        final VerificationChallenge<?> verificationChallenge = this.challengesById.get(challengeId);
        if (verificationChallenge == null) {
            throw new Gw2AccountVerificationServiceException("", HttpStatus.BAD_REQUEST);
        }

        final Object state = verificationChallenge.start();

        final String stateJson;
        try {
            stateJson = this.objectMapper.writeValueAsString(state);
        } catch (IOException e) {
            throw new Gw2AccountVerificationServiceException(Gw2AccountVerificationServiceException.INTERNAL_SERVER_ERROR, HttpStatus.INTERNAL_SERVER_ERROR);
        }

        final Locale userLocale = LocaleContextHolder.getLocale();
        final Gw2AccountVerificationChallengeEntity entity = this.gw2AccountVerificationChallengeRepository.save(
                new Gw2AccountVerificationChallengeEntity(accountId, "", challengeId, state.getClass().getName(), stateJson, null, null, null)
        );

        return new VerificationChallengeStart(entity.challengeId(), buildMessage(verificationChallenge, state, userLocale));
    }

    @Override
    @Transactional
    public VerificationChallengeSubmit submitChallenge(long accountId, String gw2ApiToken) {
        Gw2AccountVerificationChallengeEntity entity = this.gw2AccountVerificationChallengeRepository.findByAccountIdAndGw2AccountId(accountId, "")
                .orElseThrow(() -> new Gw2AccountVerificationServiceException(Gw2AccountVerificationServiceException.CHALLENGE_NOT_FOUND, HttpStatus.NOT_FOUND));

        final VerificationChallenge<?> challenge = this.challengesById.get(entity.challengeId());
        if (challenge == null) {
            this.gw2AccountVerificationChallengeRepository.deleteByAccountIdAndGw2AccountId(accountId, "");
            throw new Gw2AccountVerificationServiceException(Gw2AccountVerificationServiceException.CHALLENGE_NOT_FOUND, HttpStatus.NOT_FOUND);
        }

        final Instant startTime = Instant.now();
        final Instant timeout = startTime.plus(challenge.getTimeout());
        final Gw2SubToken gw2SubToken = this.gw2ApiService.createSubToken(gw2ApiToken, challenge.getRequiredGw2ApiPermissions(), timeout);
        final String gw2AccountId = this.gw2ApiService.getAccount(gw2ApiToken).id();

        if (!gw2SubToken.permissions().containsAll(challenge.getRequiredGw2ApiPermissions())) {
            throw new Gw2AccountVerificationServiceException(Gw2AccountVerificationServiceException.INSUFFICIENT_PERMISSIONS, HttpStatus.BAD_REQUEST);
        }

        entity = new Gw2AccountVerificationChallengeEntity(
                entity.accountId(),
                gw2AccountId,
                entity.challengeId(),
                entity.stateClass(),
                entity.state(),
                gw2ApiToken,
                startTime,
                timeout
        );

        final boolean isVerified = verify(entity);
        final VerificationChallengePending verificationChallengePending;

        if (isVerified) {
            this.gw2AccountVerificationChallengeRepository.deleteByAccountIdAndGw2AccountId(accountId, "");
            verificationChallengePending = null;
        } else {
            this.gw2AccountVerificationChallengeRepository.save(entity);
            verificationChallengePending = new VerificationChallengePending(entity.challengeId(), gw2AccountId, startTime);
        }

        return new VerificationChallengeSubmit(verificationChallengePending, isVerified);
    }

    @Transactional(noRollbackFor = Gw2AccountVerificationServiceException.class)
    protected boolean verify(Gw2AccountVerificationChallengeEntity entity) {
        final long accountId = entity.accountId();
        final String gw2AccountId = entity.gw2AccountId();

        final VerificationChallenge<?> challenge = this.challengesById.get(entity.challengeId());
        if (challenge == null) {
            this.gw2AccountVerificationChallengeRepository.deleteByAccountIdAndGw2AccountId(accountId, gw2AccountId);
            throw new Gw2AccountVerificationServiceException(Gw2AccountVerificationServiceException.CHALLENGE_NOT_FOUND, HttpStatus.NOT_FOUND);
        }

        final Optional<Object> optionalState = deserialize(entity.stateClass(), entity.state());
        if (optionalState.isEmpty()) {
            this.gw2AccountVerificationChallengeRepository.deleteByAccountIdAndGw2AccountId(accountId, gw2AccountId);
            throw new Gw2AccountVerificationServiceException(Gw2AccountVerificationServiceException.CHALLENGE_NOT_FOUND, HttpStatus.NOT_FOUND);
        }

        final Object state = optionalState.get();
        final boolean isVerified = verify(challenge, state, entity.gw2ApiToken());

        if (isVerified) {
            this.gw2AccountVerificationChallengeRepository.deleteByAccountIdAndGw2AccountId(accountId, "");
            this.gw2AccountVerificationRepository.save(
                    this.gw2AccountVerificationRepository.findById(gw2AccountId)
                            .map((e) -> e.withAccountId(accountId))
                            .orElseGet(() -> new Gw2AccountVerificationEntity(gw2AccountId, accountId))
            );
        }

        return isVerified;
    }

    @Scheduled(fixedRate = 1000L * 60L * 5L)
    public void tryVerify() {
        final Instant now = Instant.now();
        final List<Gw2AccountVerificationChallengeEntity> entities = this.gw2AccountVerificationChallengeRepository.findAllPending();

        if (!entities.isEmpty()) {
            LOG.info("processing {} pending challenges", entities.size());

            for (Gw2AccountVerificationChallengeEntity entity : entities) {
                try {
                    if (entity.timeoutAt().isBefore(now)) {
                        this.gw2AccountVerificationChallengeRepository.deleteByAccountIdAndGw2AccountId(entity.accountId(), entity.gw2AccountId());
                    } else {
                        verify(entity);
                    }
                } catch (Exception e) {
                    LOG.warn("unexpected exception during verification of challenge", e);
                }
            }
        }
    }

    private static <S> boolean verify(VerificationChallenge<S> verificationChallenge, Object state, String gw2ApiToken) {
        return verificationChallenge.verify((S) state, gw2ApiToken);
    }

    private Optional<Object> deserialize(String stateClassName, String stateJson) {
        try {
            return Optional.of(this.objectMapper.readValue(stateJson, Class.forName(stateClassName)));
        } catch (ClassNotFoundException | IOException e) {
            return Optional.empty();
        }
    }

    private static <S> Map<String, Object> buildMessage(VerificationChallenge<S> verificationChallenge, Object state, Locale locale) {
        return verificationChallenge.buildMessage((S) state, locale);
    }
}
