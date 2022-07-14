package com.gw2auth.oauth2.server.service.apitoken;

import com.gw2auth.oauth2.server.repository.apitoken.ApiTokenEntity;
import com.gw2auth.oauth2.server.repository.apitoken.ApiTokenRepository;
import com.gw2auth.oauth2.server.repository.apitoken.ApiTokenValidityUpdateEntity;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.gw2.*;
import com.gw2auth.oauth2.server.service.verification.VerificationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service
@EnableScheduling
public class ApiTokenServiceImpl implements ApiTokenService {

    private static final Logger LOG = LoggerFactory.getLogger(ApiTokenServiceImpl.class);
    private static final Duration VALIDITY_CHECK_INTERVAL = Duration.ofMinutes(45L);
    private static final int VALIDITY_CHECK_BATCH_SIZE = 50;

    private final ApiTokenRepository apiTokenRepository;
    private final Gw2ApiService gw2ApiService;
    private final VerificationService verificationService;
    private Clock clock;

    @Autowired
    public ApiTokenServiceImpl(ApiTokenRepository apiTokenRepository, Gw2ApiService gw2ApiService, VerificationService verificationService) {
        this.apiTokenRepository = apiTokenRepository;
        this.gw2ApiService = gw2ApiService;
        this.verificationService = verificationService;
        this.clock = Clock.systemUTC();
    }

    public void setClock(Clock clock) {
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public List<ApiToken> getApiTokens(UUID accountId) {
        return this.apiTokenRepository.findAllByAccountId(accountId).stream().map(ApiToken::fromEntity).collect(Collectors.toList());
    }

    @Override
    public List<ApiToken> getApiTokens(UUID accountId, Collection<UUID> gw2AccountIds) {
        if (gw2AccountIds.isEmpty()) {
            return List.of();
        }

        return this.apiTokenRepository.findAllByAccountIdAndGw2AccountIds(accountId, gw2AccountIds).stream()
                .map(ApiToken::fromEntity)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(noRollbackFor = ApiTokenOwnershipMismatchException.class)
    public ApiToken updateApiToken(UUID accountId, UUID gw2AccountId, String gw2ApiToken, String displayName) {
        final Optional<UUID> optional = this.verificationService.getVerifiedAccountId(gw2AccountId);

        if (optional.isPresent() && !optional.get().equals(accountId)) {
            this.apiTokenRepository.deleteByAccountIdAndGw2AccountId(accountId, gw2AccountId);
            throw new ApiTokenOwnershipMismatchException();
        }

        ApiTokenEntity apiTokenEntity = this.apiTokenRepository.findByAccountIdAndGw2AccountId(accountId, gw2AccountId).orElseThrow(() -> new ApiTokenServiceException(ApiTokenServiceException.API_TOKEN_NOT_FOUND, HttpStatus.NOT_FOUND));

        if (gw2ApiToken != null) {
            final Gw2TokenInfo gw2TokenInfo = this.gw2ApiService.getTokenInfo(gw2ApiToken);

            if (!gw2TokenInfo.permissions().contains(Gw2ApiPermission.ACCOUNT)) {
                throw new ApiTokenServiceException(ApiTokenServiceException.MISSING_ACCOUNT_PERMISSION, HttpStatus.BAD_REQUEST);
            }

            final Gw2Account gw2Account = this.gw2ApiService.getAccount(gw2ApiToken);

            if (!gw2Account.id().equals(gw2AccountId)) {
                throw new ApiTokenServiceException(ApiTokenServiceException.GW2_ACCOUNT_ID_MISMATCH, HttpStatus.BAD_REQUEST);
            }

            apiTokenEntity = apiTokenEntity
                    .withGw2ApiToken(gw2ApiToken)
                    .withGw2ApiPermissions(gw2TokenInfo.permissions().stream().map(Gw2ApiPermission::gw2).collect(Collectors.toSet()))
                    .withLastValidCheckTime(this.clock.instant(), true);
        }

        if (displayName != null) {
            apiTokenEntity = apiTokenEntity.withDisplayName(displayName);
        }

        return ApiToken.fromEntity(this.apiTokenRepository.save(apiTokenEntity));
    }

    @Override
    @Transactional(noRollbackFor = ApiTokenOwnershipMismatchException.class)
    public ApiToken addApiToken(UUID accountId, String gw2ApiToken) {
        final Gw2TokenInfo gw2TokenInfo = this.gw2ApiService.getTokenInfo(gw2ApiToken);

        if (!gw2TokenInfo.permissions().contains(Gw2ApiPermission.ACCOUNT)) {
            throw new ApiTokenServiceException(ApiTokenServiceException.MISSING_ACCOUNT_PERMISSION, HttpStatus.BAD_REQUEST);
        }

        final Gw2Account gw2Account = this.gw2ApiService.getAccount(gw2ApiToken);
        final Optional<ApiTokenEntity> optionalGw2ApiTokenEntity = this.apiTokenRepository.findByAccountIdAndGw2AccountId(accountId, gw2Account.id());

        if (optionalGw2ApiTokenEntity.isPresent()) {
            throw new ApiTokenServiceException(ApiTokenServiceException.API_TOKEN_ALREADY_EXISTS, HttpStatus.BAD_REQUEST);
        }

        final Optional<UUID> optional = this.verificationService.getVerifiedAccountId(gw2Account.id());

        if (optional.isPresent() && !optional.get().equals(accountId)) {
            this.apiTokenRepository.deleteByAccountIdAndGw2AccountId(accountId, gw2Account.id());
            throw new ApiTokenOwnershipMismatchException();
        }

        final Instant now = this.clock.instant();
        return ApiToken.fromEntity(this.apiTokenRepository.save(
                new ApiTokenEntity(accountId, gw2Account.id(), now, gw2ApiToken, gw2TokenInfo.permissions().stream().map(Gw2ApiPermission::gw2).collect(Collectors.toSet()), now, true, gw2Account.name())
        ));
    }

    @Override
    public void deleteApiToken(UUID accountId, UUID gw2AccountId) {
        final int deletedCount = this.apiTokenRepository.deleteByAccountIdAndGw2AccountId(accountId, gw2AccountId);

        if (deletedCount < 1) {
            throw new ApiTokenServiceException(ApiTokenServiceException.API_TOKEN_NOT_FOUND, HttpStatus.NOT_FOUND);
        } else if (deletedCount != 1) {
            LOG.warn("deleted ApiToken for specific accountId and gw2AccountId, deleted more than 1: {}", deletedCount);
        }
    }

    @Override
    public void updateApiTokensValid(Instant lastValidCheckTime, Collection<ApiTokenValidityUpdate> updates) {
        final List<ApiTokenValidityUpdateEntity> updateEntities = updates.stream()
                .map((v) -> new ApiTokenValidityUpdateEntity(v.accountId(), v.gw2AccountId(), v.isValid()))
                .collect(Collectors.toList());

        this.apiTokenRepository.updateApiTokensValid(lastValidCheckTime, updateEntities);
    }

    @Scheduled(fixedRate = 1000L * 60L * 5L)
    public void checkTokenValidity() {
        final Instant now = this.clock.instant();
        final Instant offset = now.minus(VALIDITY_CHECK_INTERVAL);

        final List<ApiTokenEntity> tokensToCheck = this.apiTokenRepository.findAllByLastValidCheckTimeLTE(offset, VALIDITY_CHECK_BATCH_SIZE);
        final List<ApiTokenValidityUpdateEntity> updateEntities = new ArrayList<>(tokensToCheck.size());
        final int[] counts = new int[3];

        for (ApiTokenEntity apiTokenEntity : tokensToCheck) {
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
                updateEntities.add(new ApiTokenValidityUpdateEntity(apiTokenEntity.accountId(), apiTokenEntity.gw2AccountId(), isValidState));
            }
        }

        this.apiTokenRepository.updateApiTokensValid(now, updateEntities);
        LOG.info("updated API-Token validity for {} API-Tokens; valid={} invalid={} unknown={}", tokensToCheck.size(), counts[0], counts[1], counts[2]);
    }
}
