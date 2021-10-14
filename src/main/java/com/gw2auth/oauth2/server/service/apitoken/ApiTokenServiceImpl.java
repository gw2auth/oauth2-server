package com.gw2auth.oauth2.server.service.apitoken;

import com.gw2auth.oauth2.server.repository.apitoken.ApiTokenEntity;
import com.gw2auth.oauth2.server.repository.apitoken.ApiTokenRepository;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.gw2.Gw2Account;
import com.gw2auth.oauth2.server.service.gw2.Gw2ApiService;
import com.gw2auth.oauth2.server.service.gw2.Gw2TokenInfo;
import com.gw2auth.oauth2.server.service.verification.VerificationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.stream.Collectors;

@Service
public class ApiTokenServiceImpl implements ApiTokenService {

    private static final Logger LOG = LoggerFactory.getLogger(ApiTokenServiceImpl.class);

    private final ApiTokenRepository apiTokenRepository;
    private final Gw2ApiService gw2ApiService;
    private final VerificationService verificationService;

    @Autowired
    public ApiTokenServiceImpl(ApiTokenRepository apiTokenRepository, Gw2ApiService gw2ApiService, VerificationService verificationService) {
        this.apiTokenRepository = apiTokenRepository;
        this.gw2ApiService = gw2ApiService;
        this.verificationService = verificationService;
    }

    @Override
    public List<ApiToken> getApiTokens(long accountId) {
        return this.apiTokenRepository.findAllByAccountId(accountId).stream().map(ApiToken::fromEntity).collect(Collectors.toList());
    }

    @Override
    public List<ApiToken> getApiTokens(long accountId, Collection<String> gw2AccountIds) {
        if (gw2AccountIds.isEmpty()) {
            return List.of();
        }

        return this.apiTokenRepository.findAllByAccountIdAndGw2AccountIds(accountId, gw2AccountIds).stream()
                .map(ApiToken::fromEntity)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional(noRollbackFor = ApiTokenOwnershipMismatchException.class)
    public ApiToken updateApiToken(long accountId, String gw2AccountId, String gw2ApiToken, String displayName) {
        final OptionalLong optional = this.verificationService.getVerifiedAccountId(gw2AccountId);

        if (optional.isPresent() && optional.getAsLong() != accountId) {
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
                    .withGw2ApiPermissions(gw2TokenInfo.permissions().stream().map(Gw2ApiPermission::gw2).collect(Collectors.toSet()));
        }

        if (displayName != null) {
            apiTokenEntity = apiTokenEntity.withDisplayName(displayName);
        }

        return ApiToken.fromEntity(this.apiTokenRepository.save(apiTokenEntity));
    }

    @Override
    @Transactional(noRollbackFor = ApiTokenOwnershipMismatchException.class)
    public ApiToken addApiToken(long accountId, String gw2ApiToken) {
        final Gw2TokenInfo gw2TokenInfo = this.gw2ApiService.getTokenInfo(gw2ApiToken);

        if (!gw2TokenInfo.permissions().contains(Gw2ApiPermission.ACCOUNT)) {
            throw new ApiTokenServiceException(ApiTokenServiceException.MISSING_ACCOUNT_PERMISSION, HttpStatus.BAD_REQUEST);
        }

        final Gw2Account gw2Account = this.gw2ApiService.getAccount(gw2ApiToken);
        final Optional<ApiTokenEntity> optionalGw2ApiTokenEntity = this.apiTokenRepository.findByAccountIdAndGw2AccountId(accountId, gw2Account.id());

        if (optionalGw2ApiTokenEntity.isPresent()) {
            throw new ApiTokenServiceException(ApiTokenServiceException.API_TOKEN_ALREADY_EXISTS, HttpStatus.BAD_REQUEST);
        }

        final OptionalLong optional = this.verificationService.getVerifiedAccountId(gw2Account.id());

        if (optional.isPresent() && optional.getAsLong() != accountId) {
            this.apiTokenRepository.deleteByAccountIdAndGw2AccountId(accountId, gw2Account.id());
            throw new ApiTokenOwnershipMismatchException();
        }

        return ApiToken.fromEntity(this.apiTokenRepository.save(
                new ApiTokenEntity(accountId, gw2Account.id(), Instant.now(), gw2ApiToken, gw2TokenInfo.permissions().stream().map(Gw2ApiPermission::gw2).collect(Collectors.toSet()), gw2Account.name())
        ));
    }

    @Override
    public void deleteApiToken(long accountId, String gw2AccountId) {
        final int deletedCount = this.apiTokenRepository.deleteByAccountIdAndGw2AccountId(accountId, gw2AccountId);

        if (deletedCount < 1) {
            throw new ApiTokenServiceException(ApiTokenServiceException.API_TOKEN_NOT_FOUND, HttpStatus.NOT_FOUND);
        } else if (deletedCount != 1) {
            LOG.warn("deleted ApiToken for specific accountId and gw2AccountId, deleted more than 1: {}", deletedCount);
        }
    }
}
