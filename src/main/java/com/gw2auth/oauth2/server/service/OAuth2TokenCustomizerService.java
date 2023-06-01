package com.gw2auth.oauth2.server.service;

import com.gw2auth.oauth2.server.repository.gw2account.subtoken.Gw2AccountApiSubtokenEntity;
import com.gw2auth.oauth2.server.repository.gw2account.subtoken.Gw2AccountApiSubtokenRepository;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.application.Application;
import com.gw2auth.oauth2.server.service.application.ApplicationService;
import com.gw2auth.oauth2.server.service.application.account.ApplicationAccount;
import com.gw2auth.oauth2.server.service.application.account.ApplicationAccountService;
import com.gw2auth.oauth2.server.service.application.client.ApplicationClient;
import com.gw2auth.oauth2.server.service.application.client.SpringRegisteredClient;
import com.gw2auth.oauth2.server.service.application.client.account.ApplicationClientAccount;
import com.gw2auth.oauth2.server.service.application.client.account.ApplicationClientAccountService;
import com.gw2auth.oauth2.server.service.application.client.authorization.ApplicationClientAuthorization;
import com.gw2auth.oauth2.server.service.application.client.authorization.ApplicationClientAuthorizationService;
import com.gw2auth.oauth2.server.service.gw2.Gw2ApiService;
import com.gw2auth.oauth2.server.service.gw2.Gw2SubToken;
import com.gw2auth.oauth2.server.service.gw2account.apitoken.Gw2AccountApiToken;
import com.gw2auth.oauth2.server.service.gw2account.apitoken.Gw2AccountApiTokenService;
import com.gw2auth.oauth2.server.service.gw2account.apitoken.Gw2AccountApiTokenValidUpdate;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUser;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUserV2;
import com.gw2auth.oauth2.server.service.gw2account.verification.Gw2AccountVerificationService;
import com.gw2auth.oauth2.server.util.Batch;
import com.gw2auth.oauth2.server.util.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.DataAccessException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;

@Service
public class OAuth2TokenCustomizerService implements OAuth2TokenCustomizer<JwtEncodingContext>, Clocked {

    private static final Logger LOG = LoggerFactory.getLogger(OAuth2TokenCustomizerService.class);
    private static final Duration AUTHORIZED_TOKEN_MIN_EXCESS_TIME = Duration.ofMinutes(20L);

    private final AccountService accountService;
    private final Gw2AccountApiTokenService gw2AccountApiTokenService;
    private final ApplicationService applicationService;
    private final ApplicationAccountService applicationAccountService;
    private final ApplicationClientAccountService applicationClientAccountService;
    private final ApplicationClientAuthorizationService applicationClientAuthorizationService;
    private final Gw2AccountVerificationService gw2AccountVerificationService;
    private final Gw2ApiService gw2APIService;
    private final Gw2AccountApiSubtokenRepository gw2AccountApiSubtokenRepository;
    private final ExecutorService gw2ApiClientExecutorService;
    private Clock clock;

    @Autowired
    public OAuth2TokenCustomizerService(AccountService accountService,
                                        Gw2AccountApiTokenService gw2AccountApiTokenService,
                                        ApplicationService applicationService,
                                        ApplicationAccountService applicationAccountService,
                                        ApplicationClientAccountService applicationClientAccountService,
                                        ApplicationClientAuthorizationService applicationClientAuthorizationService,
                                        Gw2AccountVerificationService gw2AccountVerificationService,
                                        Gw2ApiService gw2APIService,
                                        Gw2AccountApiSubtokenRepository gw2AccountApiSubtokenRepository,
                                        @Qualifier("gw2-api-client-executor-service") ExecutorService gw2ApiClientExecutorService) {

        this.accountService = accountService;
        this.gw2AccountApiTokenService = gw2AccountApiTokenService;
        this.applicationService = applicationService;
        this.applicationAccountService = applicationAccountService;
        this.applicationClientAccountService = applicationClientAccountService;
        this.applicationClientAuthorizationService = applicationClientAuthorizationService;
        this.gw2AccountVerificationService = gw2AccountVerificationService;
        this.gw2APIService = gw2APIService;
        this.gw2AccountApiSubtokenRepository = gw2AccountApiSubtokenRepository;
        this.gw2ApiClientExecutorService = gw2ApiClientExecutorService;
        this.clock = Clock.systemUTC();
    }

    @Override
    public void setClock(Clock clock) {
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    @Transactional
    public void customize(JwtEncodingContext ctx) {
        if (ctx.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
            final OAuth2Authorization authorization = ctx.getAuthorization();

            final SpringRegisteredClient registeredClient = (SpringRegisteredClient) ctx.getRegisteredClient();// the client of the application the user wants to access
            final Object oauth2User = ctx.getPrincipal().getPrincipal();// the user (intended double getPrincipal())

            if (authorization != null) {
                final UUID accountId;
                if (oauth2User instanceof Gw2AuthUser gw2AuthUser) {
                    accountId = gw2AuthUser.getAccountId();
                } else if (oauth2User instanceof Gw2AuthUserV2 gw2AuthUserV2) {
                    accountId = gw2AuthUserV2.getAccountId();
                } else {
                    throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR));
                }

                customize(ctx, authorization.getId(), accountId, registeredClient.getGw2AuthClient());
            } else {
                throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR));
            }
        }
    }

    private void customize(JwtEncodingContext ctx, String clientAuthorizationId, UUID userAccountId, ApplicationClient applicationClient) {
        final UUID applicationId = applicationClient.applicationId();
        final UUID applicationClientId = applicationClient.id();
        final ApplicationClientAuthorization authorization = this.applicationClientAuthorizationService.getApplicationClientAuthorization(userAccountId, clientAuthorizationId).orElse(null);

        if (authorization == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED));
        }

        final Application application = this.applicationService.getApplication(applicationId).orElseThrow();
        final ApplicationAccount applicationAccount = this.applicationAccountService.getApplicationAccount(userAccountId, applicationId).orElseThrow();
        final ApplicationClientAccount applicationClientAccount = this.applicationClientAccountService.getApplicationClientAccount(userAccountId, applicationClientId).orElseThrow();

        try (AccountService.LoggingContext userLogging = this.accountService.log(userAccountId, Map.of("type", "ACCESS_TOKEN", "application_id", applicationId,  "client_id", applicationClientId, "user_id", applicationAccount.accountSub()))) {
            try (AccountService.LoggingContext clientOwnerLogging = this.accountService.log(application.accountId(), Map.of("type", "oauth2.user.token.refresh", "application_id", applicationId, "client_id", applicationClientId, "user_id", applicationAccount.accountSub()))) {
                customize(ctx, userAccountId, applicationAccount, applicationClientAccount, authorization, userLogging, clientOwnerLogging);
            }
        }
    }

    private void customize(JwtEncodingContext ctx, UUID userAccountId,
                           ApplicationAccount applicationAccount,
                           ApplicationClientAccount applicationClientAccount,
                           ApplicationClientAuthorization authorization,
                           AccountService.LoggingContext userLogging,
                           AccountService.LoggingContext clientOwnerLogging) {

        final Set<String> effectiveAuthorizedScopes = new HashSet<>(applicationClientAccount.authorizedScopes());
        effectiveAuthorizedScopes.retainAll(authorization.authorizedScopes());

        final Set<UUID> authorizedGw2AccountIds = authorization.gw2AccountIds();
        final Set<Gw2ApiPermission> authorizedGw2ApiPermissions = effectiveAuthorizedScopes.stream()
                .flatMap((scope) -> Gw2ApiPermission.fromOAuth2(scope).stream())
                .collect(Collectors.toSet());

        if (authorizedGw2ApiPermissions.isEmpty() || authorizedGw2AccountIds.isEmpty()) {
            logForBoth(userLogging, clientOwnerLogging, "The consent has been removed: responding with ACCESS_DENIED");
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED));
        }

        final List<Gw2AccountApiToken> authorizedRootTokens = this.gw2AccountApiTokenService.getApiTokens(userAccountId, authorizedGw2AccountIds);

        // in theory, this should not happen since authorized-tokens and root-tokens are related via foreign key
        if (authorizedRootTokens.isEmpty()) {
            logForBoth(userLogging, clientOwnerLogging, "All linked root API Tokens have been removed: responding with ACCESS_DENIED");
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED));
        }

        final Set<UUID> verifiedGw2AccountIds;
        final boolean hasGw2AuthVerifiedScope = effectiveAuthorizedScopes.contains(ApplicationClientAccountService.GW2AUTH_VERIFIED_SCOPE);

        if (hasGw2AuthVerifiedScope) {
            verifiedGw2AccountIds = this.gw2AccountVerificationService.getVerifiedGw2AccountIds(userAccountId);
        } else {
            verifiedGw2AccountIds = Set.of();
        }

        final int gw2ApiPermissionsBitSet = Gw2ApiPermission.toBitSet(authorizedGw2ApiPermissions);
        final List<Gw2AccountApiSubtokenEntity> savedSubTokens = this.gw2AccountApiSubtokenRepository.findAllByAccountIdGw2AccountIdsAndGw2ApiPermissionsBitSet(userAccountId, authorizedGw2AccountIds, gw2ApiPermissionsBitSet);
        final Instant atLeastValidUntil = this.clock.instant().plus(AUTHORIZED_TOKEN_MIN_EXCESS_TIME);
        final Map<UUID, Gw2AccountApiSubtokenEntity> savedSubTokenByGw2AccountId = new HashMap<>(savedSubTokens.size());
        final Map<Instant, Integer> savedSubTokenCountByExpirationTime = new HashMap<>(savedSubTokens.size());
        Instant expirationTimeWithMostSavedSubTokens = null;

        // check all saved subtokens with the same permissions as this authorization
        // find the expiration time for which the most subtokens are still valid

        for (Gw2AccountApiSubtokenEntity savedSubToken : savedSubTokens) {
            if (savedSubToken.expirationTime().isAfter(atLeastValidUntil)) {
                savedSubTokenByGw2AccountId.put(savedSubToken.gw2AccountId(), savedSubToken);

                final int groupCount = savedSubTokenCountByExpirationTime.merge(savedSubToken.expirationTime(), 1, Integer::sum);

                if (expirationTimeWithMostSavedSubTokens == null || groupCount > savedSubTokenCountByExpirationTime.get(expirationTimeWithMostSavedSubTokens)) {
                    expirationTimeWithMostSavedSubTokens = savedSubToken.expirationTime();
                }
            }
        }

        final Instant expirationTime;

        if (expirationTimeWithMostSavedSubTokens != null) {
            // if existing subtokens which are still valid for at least AUTHORIZED_TOKEN_MIN_EXCESS_TIME could be found, use this expiration time
            ctx.getClaims().expiresAt(expirationTimeWithMostSavedSubTokens);
            expirationTime = expirationTimeWithMostSavedSubTokens;
        } else {
            expirationTime = ctx.getClaims().build().getExpiresAt();
        }

        final Map<UUID, Map<String, Object>> tokensForJWT = new LinkedHashMap<>(authorizedGw2AccountIds.size());
        final Batch.Builder<Map<UUID, Pair<Gw2AccountApiToken, Gw2SubToken>>> batch = Batch.builder();

        for (Gw2AccountApiToken authorizedRootToken : authorizedRootTokens) {
            final Map<String, Object> tokenForJWT = new HashMap<>(3);

            final UUID gw2AccountId = authorizedRootToken.gw2AccountId();
            final String displayName = authorizedRootToken.displayName();
            final Gw2AccountApiSubtokenEntity potentialExistingSubToken = savedSubTokenByGw2AccountId.get(gw2AccountId);

            tokenForJWT.put("name", displayName);

            if (potentialExistingSubToken != null && potentialExistingSubToken.expirationTime().equals(expirationTime)) {
                tokenForJWT.put("token", potentialExistingSubToken.gw2ApiSubtoken());
                logForBoth(userLogging, clientOwnerLogging, String.format("Using existing and valid subtoken for the root API Token named '%s'", displayName));
            } else {
                if (authorizedRootToken.gw2ApiPermissions().containsAll(authorizedGw2ApiPermissions)) {
                    final String gw2ApiToken = authorizedRootToken.gw2ApiToken();

                    batch.add(
                            (timeout) -> this.gw2APIService.withTimeout(timeout, () -> this.gw2APIService.createSubToken(gw2ApiToken, authorizedGw2ApiPermissions, expirationTime)),
                            (accumulator, context) -> {
                                try {
                                    accumulator.put(gw2AccountId, new Pair<>(authorizedRootToken, context.get()));
                                } catch (ExecutionException | TimeoutException e) {
                                    accumulator.put(gw2AccountId, new Pair<>(authorizedRootToken, null));
                                } catch (InterruptedException e) {
                                    Thread.currentThread().interrupt();
                                    accumulator.put(gw2AccountId, new Pair<>(authorizedRootToken, null));
                                }

                                return accumulator;
                            }
                    );
                } else {
                    tokenForJWT.put("error", "Failed to obtain new subtoken");
                    logForBoth(userLogging, clientOwnerLogging, String.format("The root API Token named '%s' has less permissions than the authorization", displayName));
                }
            }

            if (hasGw2AuthVerifiedScope) {
                final boolean isVerified = verifiedGw2AccountIds.contains(gw2AccountId);
                tokenForJWT.put("verified", isVerified);
                logForBoth(userLogging, clientOwnerLogging, String.format("Including verified=%s for the root API Token named '%s'", isVerified, displayName));
            }

            tokensForJWT.put(gw2AccountId, tokenForJWT);
        }

        final Map<UUID, Pair<Gw2AccountApiToken, Gw2SubToken>> result = batch.build().execute(this.gw2ApiClientExecutorService, HashMap::new, 10L, TimeUnit.SECONDS);
        final List<Gw2AccountApiTokenValidUpdate> apiTokenValidityUpdates = new ArrayList<>(result.size());
        final List<Gw2AccountApiSubtokenEntity> apiSubTokenEntitiesToSave = new ArrayList<>(result.size());

        for (Map.Entry<UUID, Pair<Gw2AccountApiToken, Gw2SubToken>> entry : result.entrySet()) {
            final UUID gw2AccountId = entry.getKey();
            final Map<String, Object> tokenForJWT = tokensForJWT.get(gw2AccountId);
            final String displayName = entry.getValue().v1().displayName();
            final Gw2SubToken gw2SubToken = entry.getValue().v2();

            if (gw2SubToken != null) {
                if (gw2SubToken.permissions().equals(authorizedGw2ApiPermissions)) {
                    apiSubTokenEntitiesToSave.add(new Gw2AccountApiSubtokenEntity(userAccountId, gw2AccountId, gw2ApiPermissionsBitSet, gw2SubToken.value(), expirationTime));

                    tokenForJWT.put("token", gw2SubToken.value());
                    logForBoth(userLogging, clientOwnerLogging, String.format("Added subtoken for the root API Token named '%s'", displayName));
                } else {
                    tokenForJWT.put("error", "Failed to obtain new subtoken");
                    logForBoth(userLogging, clientOwnerLogging, String.format("The retrieved subtoken for the root API Token named '%s' appears to have less permissions than the authorization", displayName));
                }

                apiTokenValidityUpdates.add(new Gw2AccountApiTokenValidUpdate(userAccountId, gw2AccountId, true));
            } else {
                tokenForJWT.put("error", "Failed to obtain new subtoken");
                logForBoth(userLogging, clientOwnerLogging, String.format("Failed to retrieve a new subtoken for the root API Token named '%s' from the GW2 API", displayName));
            }
        }

        final List<Runnable> failSafeRunnables = List.of(
                () -> this.gw2AccountApiTokenService.updateApiTokensValid(this.clock.instant(), apiTokenValidityUpdates),
                () -> this.gw2AccountApiSubtokenRepository.saveAll(apiSubTokenEntitiesToSave)
        );

        for (Runnable failSafeRunnable : failSafeRunnables) {
            try {
                failSafeRunnable.run();
            } catch (DataAccessException e) {
                LOG.info("failed to save low priority entity (one of [api token validity], [api subtoken])", e);
            }
        }

        customize(ctx, applicationAccount.accountSub(), authorizedGw2ApiPermissions, tokensForJWT);
    }

    private void customize(JwtEncodingContext ctx, UUID accountSub, Set<Gw2ApiPermission> authorizedGw2ApiPermissions, Map<UUID, Map<String, Object>> tokensForJWT) {
        final List<String> permissionsForJWT = authorizedGw2ApiPermissions.stream()
                .map(Gw2ApiPermission::gw2)
                .collect(Collectors.toList());

        ctx.getClaims()
                .subject(accountSub.toString())
                .claim("gw2:permissions", permissionsForJWT)
                .claim("gw2:tokens", tokensForJWT);
    }

    private static void logForBoth(AccountService.LoggingContext log1, AccountService.LoggingContext log2, String message) {
        log1.log(message);
        log2.log(message);
    }
}
