package com.gw2auth.oauth2.server.service;

import com.gw2auth.oauth2.server.repository.gw2account.subtoken.Gw2AccountApiSubtokenEntity;
import com.gw2auth.oauth2.server.repository.gw2account.subtoken.Gw2AccountApiSubtokenRepository;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.application.Application;
import com.gw2auth.oauth2.server.service.application.ApplicationService;
import com.gw2auth.oauth2.server.service.application.account.ApplicationAccount;
import com.gw2auth.oauth2.server.service.application.account.ApplicationAccountService;
import com.gw2auth.oauth2.server.service.application.client.ApplicationClient;
import com.gw2auth.oauth2.server.service.application.client.ApplicationClientService;
import com.gw2auth.oauth2.server.service.application.client.SpringRegisteredClient;
import com.gw2auth.oauth2.server.service.application.client.account.ApplicationClientAccount;
import com.gw2auth.oauth2.server.service.application.client.account.ApplicationClientAccountService;
import com.gw2auth.oauth2.server.service.application.client.authorization.ApplicationClientAuthorization;
import com.gw2auth.oauth2.server.service.application.client.authorization.ApplicationClientAuthorizationService;
import com.gw2auth.oauth2.server.service.gw2.Gw2ApiService;
import com.gw2auth.oauth2.server.service.gw2.Gw2SubToken;
import com.gw2auth.oauth2.server.service.gw2account.Gw2Account;
import com.gw2auth.oauth2.server.service.gw2account.Gw2AccountService;
import com.gw2auth.oauth2.server.service.gw2account.Gw2AccountWithOptionalApiToken;
import com.gw2auth.oauth2.server.service.gw2account.apitoken.Gw2AccountApiTokenService;
import com.gw2auth.oauth2.server.service.gw2account.apitoken.Gw2AccountApiTokenValidUpdate;
import com.gw2auth.oauth2.server.service.gw2account.verification.Gw2AccountVerificationService;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUser;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUserV2;
import com.gw2auth.oauth2.server.util.Batch;
import com.gw2auth.oauth2.server.util.Pair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.ByteBuffer;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class OAuth2TokenCustomizerService implements OAuth2TokenCustomizer<JwtEncodingContext>, Clocked {

    private static final Duration AUTHORIZED_TOKEN_MIN_EXCESS_TIME = Duration.ofMinutes(20L);

    private final AccountService accountService;
    private final Gw2AccountService gw2AccountService;
    private final Gw2AccountApiTokenService gw2AccountApiTokenService;
    private final ApplicationService applicationService;
    private final ApplicationAccountService applicationAccountService;
    private final ApplicationClientService applicationClientService;
    private final ApplicationClientAccountService applicationClientAccountService;
    private final ApplicationClientAuthorizationService applicationClientAuthorizationService;
    private final Gw2AccountVerificationService gw2AccountVerificationService;
    private final Gw2ApiService gw2APIService;
    private final Gw2AccountApiSubtokenRepository gw2AccountApiSubtokenRepository;
    private final ExecutorService gw2ApiClientExecutorService;
    private final ExecutorService asyncTasksExecutorService;
    private Clock clock;

    @Autowired
    public OAuth2TokenCustomizerService(AccountService accountService,
                                        Gw2AccountService gw2AccountService,
                                        Gw2AccountApiTokenService gw2AccountApiTokenService,
                                        ApplicationService applicationService,
                                        ApplicationClientService applicationClientService,
                                        ApplicationAccountService applicationAccountService,
                                        ApplicationClientAccountService applicationClientAccountService,
                                        ApplicationClientAuthorizationService applicationClientAuthorizationService,
                                        Gw2AccountVerificationService gw2AccountVerificationService,
                                        Gw2ApiService gw2APIService,
                                        Gw2AccountApiSubtokenRepository gw2AccountApiSubtokenRepository,
                                        @Qualifier("gw2-api-client-executor-service") ExecutorService gw2ApiClientExecutorService,
                                        @Qualifier("async-tasks-executor-service") ExecutorService asyncTasksExecutorService) {

        this.accountService = accountService;
        this.gw2AccountService = gw2AccountService;
        this.gw2AccountApiTokenService = gw2AccountApiTokenService;
        this.applicationService = applicationService;
        this.applicationClientService = applicationClientService;
        this.applicationAccountService = applicationAccountService;
        this.applicationClientAccountService = applicationClientAccountService;
        this.applicationClientAuthorizationService = applicationClientAuthorizationService;
        this.gw2AccountVerificationService = gw2AccountVerificationService;
        this.gw2APIService = gw2APIService;
        this.gw2AccountApiSubtokenRepository = gw2AccountApiSubtokenRepository;
        this.gw2ApiClientExecutorService = gw2ApiClientExecutorService;
        this.asyncTasksExecutorService = asyncTasksExecutorService;
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

            final RegisteredClient registeredClient = ctx.getRegisteredClient();// the client of the application the user wants to access
            final ApplicationClient applicationClient;

            if (registeredClient instanceof SpringRegisteredClient springRegisteredClient) {
                applicationClient = springRegisteredClient.getGw2AuthClient();
            } else {
                final UUID clientId = UUID.fromString(registeredClient.getClientId());
                applicationClient = this.applicationClientService.getApplicationClients(List.of(clientId)).getFirst();
            }

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

                customizeTokenForAuthorization(ctx, authorization.getId(), accountId, applicationClient);
            } else {
                throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR));
            }
        }
    }

    private void customizeTokenForAuthorization(JwtEncodingContext ctx,
                                                String clientAuthorizationId,
                                                UUID userAccountId,
                                                ApplicationClient applicationClient) {

        final UUID applicationId = applicationClient.applicationId();
        final UUID applicationClientId = applicationClient.id();
        final ApplicationClientAuthorization authorization = this.applicationClientAuthorizationService.getApplicationClientAuthorization(userAccountId, clientAuthorizationId).orElse(null);

        if (authorization == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED));
        }

        final Application application = this.applicationService.getApplication(applicationId).orElseThrow();
        final ApplicationAccount applicationAccount = this.applicationAccountService.getApplicationAccount(userAccountId, applicationId).orElseThrow();
        final ApplicationClientAccount applicationClientAccount = this.applicationClientAccountService.getApplicationClientAccount(userAccountId, applicationClientId).orElseThrow();

        try (AccountService.LoggingContext logging = this.accountService.log(userAccountId, Map.of("type", "ACCESS_TOKEN", "application_id", applicationId,  "client_id", applicationClientId, "user_id", applicationAccount.accountSub()))) {
            customizeTokenForAuthorizationWithClientApiVersion(applicationClient.apiVersion(), ctx, userAccountId, applicationAccount, applicationClientAccount, authorization, logging);
        }
    }

    private void customizeTokenForAuthorizationWithClientApiVersion(OAuth2ClientApiVersion clientApiVersion,
                                                                    JwtEncodingContext ctx,
                                                                    UUID userAccountId,
                                                                    ApplicationAccount applicationAccount,
                                                                    ApplicationClientAccount applicationClientAccount,
                                                                    ApplicationClientAuthorization authorization,
                                                                    AccountService.LoggingContext _logging) {

        final Set<UUID> authorizedGw2AccountIds = authorization.gw2AccountIds();
        final Set<OAuth2Scope> effectiveAuthorizedScopes = authorization.authorizedScopes().stream()
                .filter(applicationClientAccount.authorizedScopes()::contains)
                .collect(Collectors.toUnmodifiableSet());

        try (AccountService.LoggingContext logging = _logging.with(Map.of("client_api_version", clientApiVersion))) {
            logging.log("Preparing new OAuth2 Access-Token JWT");

            switch (clientApiVersion) {
                case V0 -> customizeTokenForV0(ctx, userAccountId, applicationAccount.accountSub(), effectiveAuthorizedScopes, authorizedGw2AccountIds, logging);
                case V1 -> customizeTokenForV1(ctx, userAccountId, applicationAccount.accountSub(), effectiveAuthorizedScopes, authorizedGw2AccountIds, logging);
                default -> throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR));
            }
        }
    }

    private void customizeTokenForV0(JwtEncodingContext ctx,
                                     UUID userAccountId,
                                     UUID userAccountSub,
                                     Set<OAuth2Scope> scopes,
                                     Set<UUID> gw2AccountIds,
                                     AccountService.LoggingContext logging) {

        final Set<Gw2ApiPermission> gw2ApiPermissions = scopes.stream()
                .flatMap((scope) -> Gw2ApiPermission.fromScope(scope).stream())
                .collect(Collectors.toUnmodifiableSet());

        if (gw2ApiPermissions.isEmpty() || gw2AccountIds.isEmpty()) {
            logging.log("The consent has been removed: responding with ACCESS_DENIED");
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED));
        }

        final Map<UUID, Gw2AccountWithOptionalApiToken> accountsWithTokenByGw2AccountId = this.gw2AccountService.getWithOptionalApiTokens(userAccountId, gw2AccountIds).stream()
                .collect(Collectors.toMap((v) -> v.account().gw2AccountId(), Function.identity()));

        if (accountsWithTokenByGw2AccountId.isEmpty()) {
            logging.log("All linked root API Tokens have been removed: responding with ACCESS_DENIED");
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED));
        }

        final Set<UUID> verifiedGw2AccountIds;
        final boolean hasGw2authVerifiedScope = scopes.contains(OAuth2Scope.GW2AUTH_VERIFIED);

        if (hasGw2authVerifiedScope) {
            verifiedGw2AccountIds = this.gw2AccountVerificationService.getVerifiedGw2AccountIds(userAccountId);
        } else {
            verifiedGw2AccountIds = Set.of();
        }

        final Pair<Instant, Map<UUID, String>> subTokensResult = getSubTokens(
                userAccountId,
                gw2AccountIds,
                gw2ApiPermissions,
                accountsWithTokenByGw2AccountId,
                ctx.getClaims().build().getExpiresAt(),
                logging
        );
        final Instant expirationTime = subTokensResult.v1();
        final Map<UUID, String> subTokensByGw2AccountId = subTokensResult.v2();

        ctx.getClaims().expiresAt(expirationTime);

        final Map<UUID, Map<String, Object>> tokensForJWT = new LinkedHashMap<>(gw2AccountIds.size());
        for (UUID gw2AccountId : gw2AccountIds) {
            try (AccountService.LoggingContext gw2AccountLogging = logging.with(Map.of("gw2_account_id", gw2AccountId))) {
                final Gw2AccountWithOptionalApiToken accountWithToken = accountsWithTokenByGw2AccountId.get(gw2AccountId);

                if (accountWithToken != null) {
                    final Gw2Account account = accountWithToken.account();
                    final String subToken = subTokensByGw2AccountId.get(gw2AccountId);
                    final String displayName = account.displayName();

                    final Map<String, Object> tokenForJWT = new HashMap<>(3);
                    tokenForJWT.put("name", displayName);

                    if (subToken != null) {
                        tokenForJWT.put("token", subToken);
                        gw2AccountLogging.log("Added subtoken to the JWT");
                    } else {
                        tokenForJWT.put("error", "Failed to obtain new subtoken");
                        gw2AccountLogging.log("No subtoken available to add to the JWT");
                    }

                    if (hasGw2authVerifiedScope) {
                        final boolean isVerified = verifiedGw2AccountIds.contains(gw2AccountId);
                        tokenForJWT.put("verified", isVerified);
                        gw2AccountLogging.log(String.format("Including verified=%s to the JWT", isVerified));
                    }

                    tokensForJWT.put(gw2AccountId, tokenForJWT);
                }
            }
        }

        final List<String> permissionsForJWT = gw2ApiPermissions.stream()
                .map(Gw2ApiPermission::gw2)
                .collect(Collectors.toList());

        ctx.getClaims()
                .subject(userAccountSub.toString())
                .claim("gw2:permissions", permissionsForJWT)
                .claim("gw2:tokens", tokensForJWT);
    }

    private void customizeTokenForV1(JwtEncodingContext ctx,
                                     UUID userAccountId,
                                     UUID userAccountSub,
                                     Set<OAuth2Scope> scopes,
                                     Set<UUID> gw2AccountIds,
                                     AccountService.LoggingContext logging) {

        if (OAuth2Scope.containsAnyGw2AccountRelatedScopes(scopes)) {
            final Map<UUID, Gw2AccountWithOptionalApiToken> accountsWithTokenByGw2AccountId = this.gw2AccountService.getWithOptionalApiTokens(userAccountId, gw2AccountIds).stream()
                    .collect(Collectors.toMap((v) -> v.account().gw2AccountId(), Function.identity()));

            final Set<Gw2ApiPermission> gw2ApiPermissions = scopes.stream()
                    .flatMap((scope) -> Gw2ApiPermission.fromScope(scope).stream())
                    .collect(Collectors.toUnmodifiableSet());

            final Set<UUID> verifiedGw2AccountIds;
            final Map<UUID, String> subTokensByGw2AccountId;

            if (scopes.contains(OAuth2Scope.GW2ACC_VERIFIED)) {
                verifiedGw2AccountIds = this.gw2AccountVerificationService.getVerifiedGw2AccountIds(userAccountId);
            } else {
                verifiedGw2AccountIds = Set.of();
            }

            if (gw2ApiPermissions.isEmpty()) {
                subTokensByGw2AccountId = Map.of();
            } else {
                final Pair<Instant, Map<UUID, String>> subTokensResult = getSubTokens(
                        userAccountId,
                        gw2AccountIds,
                        gw2ApiPermissions,
                        accountsWithTokenByGw2AccountId,
                        ctx.getClaims().build().getExpiresAt(),
                        logging
                );
                final Instant expirationTime = subTokensResult.v1();
                subTokensByGw2AccountId = subTokensResult.v2();

                ctx.getClaims().expiresAt(expirationTime);
            }

            final List<Map<String, Object>> gw2AccountsForJWT = new ArrayList<>(gw2AccountIds.size());

            for (UUID gw2AccountId : gw2AccountIds) {
                try (AccountService.LoggingContext gw2AccountLogging = logging.with(Map.of("gw2_account_id", gw2AccountId))) {
                    final Gw2AccountWithOptionalApiToken accountWithToken = accountsWithTokenByGw2AccountId.get(gw2AccountId);

                    if (accountWithToken != null) {
                        final Gw2Account account = accountWithToken.account();

                        final Map<String, Object> gw2AccountForJWT = new HashMap<>(4);
                        gw2AccountForJWT.put("id", gw2AccountId.toString());

                        if (scopes.contains(OAuth2Scope.GW2ACC_NAME)) {
                            final String gw2AccountName = account.gw2AccountName();
                            gw2AccountForJWT.put("name", gw2AccountName);
                            gw2AccountLogging.log(String.format("Including Name %s", gw2AccountName));
                        }

                        if (scopes.contains(OAuth2Scope.GW2ACC_DISPLAY_NAME)) {
                            final String displayName = account.displayName();
                            gw2AccountForJWT.put("display_name", displayName);
                            gw2AccountLogging.log(String.format("Including Displayname %s", displayName));
                        }

                        if (scopes.contains(OAuth2Scope.GW2ACC_VERIFIED)) {
                            final boolean isVerified = verifiedGw2AccountIds.contains(gw2AccountId);
                            gw2AccountForJWT.put("verified", isVerified);
                            gw2AccountLogging.log(String.format("Including verified=%s to the JWT", isVerified));
                        }

                        if (!gw2ApiPermissions.isEmpty()) {
                            final String subToken = subTokensByGw2AccountId.get(gw2AccountId);

                            if (subToken != null) {
                                gw2AccountForJWT.put("token", subToken);
                                gw2AccountLogging.log("Added subtoken to the JWT");
                            } else {
                                gw2AccountForJWT.put("error", "Failed to obtain new subtoken");
                                gw2AccountLogging.log("No subtoken available to add to the JWT");
                            }
                        }

                        gw2AccountsForJWT.add(gw2AccountForJWT);
                    }
                }
            }

            ctx.getClaims().claim("gw2_accounts", gw2AccountsForJWT);
        }

        if (scopes.contains(OAuth2Scope.ID)) {
            ctx.getClaims().subject(userAccountSub.toString());
            logging.log("Including subject");
        } else {
            final byte[] buf = ByteBuffer.allocate(Long.BYTES * 3)
                    .putLong(userAccountSub.getLeastSignificantBits())
                    .putLong(userAccountSub.getMostSignificantBits())
                    .putLong(ThreadLocalRandom.current().nextLong())
                    .array();

            final UUID sub = UUID.nameUUIDFromBytes(buf);
            ctx.getClaims().subject("RETRACTED-" + sub);

            logging.log(String.format("Not including subject: id scope not requested; including %s", sub));
        }
    }

    private Pair<Instant, Map<UUID, String>> getSubTokens(UUID userAccountId,
                                                          Set<UUID> gw2AccountIds,
                                                          Set<Gw2ApiPermission> gw2ApiPermissions,
                                                          Map<UUID, Gw2AccountWithOptionalApiToken> accountsWithTokenByGw2AccountId,
                                                          Instant expirationTime,
                                                          AccountService.LoggingContext _logging) {

        final int gw2ApiPermissionsBitSet = Gw2ApiPermission.toBitSet(gw2ApiPermissions);
        final List<Gw2AccountApiSubtokenEntity> savedSubTokens = this.gw2AccountApiSubtokenRepository.findAllByAccountIdGw2AccountIdsAndGw2ApiPermissionsBitSet(userAccountId, gw2AccountIds, gw2ApiPermissionsBitSet);
        final Instant now = this.clock.instant();
        final Instant atLeastValidUntil = now.plus(AUTHORIZED_TOKEN_MIN_EXCESS_TIME);
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

        if (expirationTimeWithMostSavedSubTokens != null) {
            expirationTime = expirationTimeWithMostSavedSubTokens;
        }

        // the batch to retrieve new subtokens
        final Batch.Builder<Map<UUID, Gw2SubToken>> batch = Batch.builder();

        // the overall result of subtokens (both already existing ones and new ones)
        final Map<UUID, String> result = new HashMap<>(gw2AccountIds.size());

        for (UUID gw2AccountId : gw2AccountIds) {
            try (AccountService.LoggingContext logging = _logging.with(Map.of("gw2_account_id", gw2AccountId))) {
                final Gw2AccountApiSubtokenEntity potentialExistingSubToken = savedSubTokenByGw2AccountId.get(gw2AccountId);

                if (potentialExistingSubToken != null && potentialExistingSubToken.expirationTime().equals(expirationTime)) {
                    result.put(gw2AccountId, potentialExistingSubToken.gw2ApiSubtoken());
                    logging.log("Using existing and valid subtoken");
                } else {
                    final Gw2AccountWithOptionalApiToken accountWithToken = accountsWithTokenByGw2AccountId.get(gw2AccountId);

                    if (accountWithToken != null
                            && accountWithToken.optionalApiToken().isPresent()
                            && accountWithToken.optionalApiToken().orElseThrow().gw2ApiPermissions().containsAll(gw2ApiPermissions)) {

                        final Instant fExpirationTime = expirationTime;
                        final String gw2ApiToken = accountWithToken.optionalApiToken().orElseThrow().gw2ApiToken();

                        batch.add(
                                (timeout) -> this.gw2APIService.withTimeout(timeout, () -> this.gw2APIService.createSubToken(gw2ApiToken, gw2ApiPermissions, fExpirationTime)),
                                (accumulator, context) -> {
                                    try {
                                        accumulator.put(gw2AccountId, context.get());
                                    } catch (ExecutionException | TimeoutException e) {
                                        accumulator.put(gw2AccountId, null);
                                    } catch (InterruptedException e) {
                                        Thread.currentThread().interrupt();
                                        accumulator.put(gw2AccountId, null);
                                    }

                                    return accumulator;
                                }
                        );

                        logging.log("Requesting a new subtoken");
                    } else {
                        logging.log("No API Token with sufficient permissions found for this GW2 Account");
                    }
                }
            }
        }

        final Map<UUID, Gw2SubToken> newSubtokensResult = batch.build().execute(this.gw2ApiClientExecutorService, HashMap::new, 10L, TimeUnit.SECONDS);
        final List<Gw2AccountApiTokenValidUpdate> apiTokenValidityUpdates = new ArrayList<>(newSubtokensResult.size());
        final List<Gw2AccountApiSubtokenEntity> apiSubTokenEntitiesToSave = new ArrayList<>(newSubtokensResult.size());

        for (Map.Entry<UUID, Gw2SubToken> entry : newSubtokensResult.entrySet()) {
            final UUID gw2AccountId = entry.getKey();

            try (AccountService.LoggingContext logging = _logging.with(Map.of("gw2_account_id", gw2AccountId))) {
                final Gw2SubToken gw2SubToken = entry.getValue();

                if (gw2SubToken != null) {
                    if (gw2SubToken.permissions().equals(gw2ApiPermissions)) {
                        apiSubTokenEntitiesToSave.add(new Gw2AccountApiSubtokenEntity(userAccountId, gw2AccountId, gw2ApiPermissionsBitSet, gw2SubToken.value(), expirationTime));
                        result.put(gw2AccountId, gw2SubToken.value());
                        logging.log("Using a new subtoken for this GW2 Account");
                    } else {
                        logging.log("The returned subtoken for this GW2 Account has less permissions than requested");
                    }

                    apiTokenValidityUpdates.add(new Gw2AccountApiTokenValidUpdate(userAccountId, gw2AccountId, true));
                } else {
                    logging.log("Failed to retrieve a new subtoken for this GW2 Account");
                }
            }
        }

        this.asyncTasksExecutorService.submit(() -> this.gw2AccountApiTokenService.updateApiTokensValid(now, apiTokenValidityUpdates));
        this.asyncTasksExecutorService.submit(() -> this.gw2AccountApiSubtokenRepository.saveAll(apiSubTokenEntitiesToSave));

        return new Pair<>(expirationTime, result);
    }
}
