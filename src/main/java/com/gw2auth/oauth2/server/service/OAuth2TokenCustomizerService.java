package com.gw2auth.oauth2.server.service;

import com.gw2auth.oauth2.server.repository.apisubtoken.ApiSubTokenEntity;
import com.gw2auth.oauth2.server.repository.apisubtoken.ApiSubTokenRepository;
import com.gw2auth.oauth2.server.service.apitoken.ApiToken;
import com.gw2auth.oauth2.server.service.apitoken.ApiTokenService;
import com.gw2auth.oauth2.server.service.client.authorization.ClientAuthorization;
import com.gw2auth.oauth2.server.service.client.authorization.ClientAuthorizationService;
import com.gw2auth.oauth2.server.service.client.consent.ClientConsent;
import com.gw2auth.oauth2.server.service.client.consent.ClientConsentService;
import com.gw2auth.oauth2.server.service.gw2.Gw2ApiService;
import com.gw2auth.oauth2.server.service.gw2.Gw2SubToken;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUser;
import com.gw2auth.oauth2.server.service.verification.VerificationService;
import com.gw2auth.oauth2.server.util.Batch;
import com.gw2auth.oauth2.server.util.Pair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
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
public class OAuth2TokenCustomizerService implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private static final Duration AUTHORIZED_TOKEN_MIN_EXCESS_TIME = Duration.ofMinutes(20L);

    private final ApiTokenService apiTokenService;
    private final ClientAuthorizationService clientAuthorizationService;
    private final ClientConsentService clientConsentService;
    private final VerificationService verificationService;
    private final Gw2ApiService gw2APIService;
    private final ApiSubTokenRepository apiSubTokenRepository;
    private final ExecutorService gw2ApiClientExecutorService;
    private volatile Clock clock;

    @Autowired
    public OAuth2TokenCustomizerService(ApiTokenService apiTokenService,
                                        ClientAuthorizationService clientAuthorizationService,
                                        ClientConsentService clientConsentService,
                                        VerificationService verificationService,
                                        Gw2ApiService gw2APIService,
                                        ApiSubTokenRepository apiSubTokenRepository,
                                        @Qualifier("gw2-api-client-executor-service") ExecutorService gw2ApiClientExecutorService) {

        this.apiTokenService = apiTokenService;
        this.clientAuthorizationService = clientAuthorizationService;
        this.clientConsentService = clientConsentService;
        this.verificationService = verificationService;
        this.gw2APIService = gw2APIService;
        this.apiSubTokenRepository = apiSubTokenRepository;
        this.gw2ApiClientExecutorService = gw2ApiClientExecutorService;
        this.clock = Clock.systemDefaultZone();
    }

    public void setClock(Clock clock) {
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    @Transactional
    public void customize(JwtEncodingContext ctx) {
        if (ctx.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
            final OAuth2Authorization authorization = ctx.getAuthorization();

            final RegisteredClient registeredClient = ctx.getRegisteredClient();// the client of the application the user wants to access
            final OAuth2AuthenticationToken auth = ctx.getPrincipal();
            final OAuth2User oAuth2User = auth.getPrincipal();// the user

            if (authorization != null && oAuth2User instanceof Gw2AuthUser) {
                final long accountId = ((Gw2AuthUser) oAuth2User).getAccountId();
                final long clientRegistrationId = Long.parseLong(registeredClient.getId());

                customize(ctx, authorization.getId(), accountId, clientRegistrationId);
            } else {
                throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR));
            }
        }
    }

    private void customize(JwtEncodingContext ctx, String clientAuthorizationId, long accountId, long clientRegistrationId) {
        final ClientAuthorization clientAuthorization = this.clientAuthorizationService.getClientAuthorization(accountId, clientAuthorizationId).orElse(null);
        final ClientConsent clientConsent = this.clientConsentService.getClientConsent(accountId, clientRegistrationId).orElse(null);

        if (clientAuthorization == null || clientConsent == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED));
        }

        try (ClientConsentService.LoggingContext logging = this.clientConsentService.log(accountId, clientRegistrationId, ClientConsentService.LogType.ACCESS_TOKEN)) {
            final Set<String> effectiveAuthorizedScopes = new HashSet<>(clientConsent.authorizedScopes());
            effectiveAuthorizedScopes.retainAll(clientAuthorization.authorizedScopes());

            final Set<String> authorizedGw2AccountIds = clientAuthorization.gw2AccountIds();
            final Set<Gw2ApiPermission> authorizedGw2ApiPermissions = effectiveAuthorizedScopes.stream()
                    .flatMap((scope) -> Gw2ApiPermission.fromOAuth2(scope).stream())
                    .collect(Collectors.toSet());

            if (authorizedGw2ApiPermissions.isEmpty() || authorizedGw2AccountIds.isEmpty()) {
                logging.log("The Consent has been removed: responding with ACCESS_DENIED");
                throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED));
            }

            final List<ApiToken> authorizedRootTokens = this.apiTokenService.getApiTokens(accountId, authorizedGw2AccountIds);

            // in theory, this should not happen since authorized-tokens and root-tokens are related via foreign key
            if (authorizedRootTokens.isEmpty()) {
                logging.log("All linked Root-API-Tokens have been removed: responding with ACCESS_DENIED");
                throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED));
            }

            final Set<String> verifiedGw2AccountIds;
            final boolean hasGw2AuthVerifiedScope = effectiveAuthorizedScopes.contains(ClientConsentService.GW2AUTH_VERIFIED_SCOPE);

            if (hasGw2AuthVerifiedScope) {
                verifiedGw2AccountIds = this.verificationService.getVerifiedGw2AccountIds(accountId);
            } else {
                verifiedGw2AccountIds = Set.of();
            }

            final int gw2ApiPermissionsBitSet = Gw2ApiPermission.toBitSet(authorizedGw2ApiPermissions);
            final List<ApiSubTokenEntity> savedSubTokens = this.apiSubTokenRepository.findAllByAccountIdGw2AccountIdsAndGw2ApiPermissionsBitSet(accountId, authorizedGw2AccountIds, gw2ApiPermissionsBitSet);
            final Instant atLeastValidUntil = this.clock.instant().plus(AUTHORIZED_TOKEN_MIN_EXCESS_TIME);
            final Map<String, ApiSubTokenEntity> savedSubTokenByGw2AccountId = new HashMap<>(savedSubTokens.size());
            final Map<Instant, Integer> savedSubTokenCountByExpirationTime = new HashMap<>(savedSubTokens.size());
            Instant expirationTimeWithMostSavedSubTokens = null;

            // check all saved subtokens with the same permissions as this authorization
            // find the expiration time for which the most subtokens are still valid

            for (ApiSubTokenEntity savedSubToken : savedSubTokens) {
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

            final Map<String, Map<String, Object>> tokensForJWT = new LinkedHashMap<>(authorizedGw2AccountIds.size());
            final Batch.Builder<Map<String, Pair<ApiToken, Gw2SubToken>>> batch = Batch.builder();

            for (ApiToken authorizedRootToken : authorizedRootTokens) {
                final Map<String, Object> tokenForJWT = new HashMap<>(3);

                final String gw2AccountId = authorizedRootToken.gw2AccountId();
                final String displayName = authorizedRootToken.displayName();
                final ApiSubTokenEntity potentialExistingSubToken = savedSubTokenByGw2AccountId.get(gw2AccountId);

                tokenForJWT.put("name", displayName);

                if (potentialExistingSubToken != null && potentialExistingSubToken.expirationTime().equals(expirationTime)) {
                    tokenForJWT.put("token", potentialExistingSubToken.gw2ApiSubtoken());
                    logging.log("Using existing and valid Subtoken for the Root-API-Token named '%s'", displayName);
                } else {
                    if (authorizedRootToken.gw2ApiPermissions().containsAll(authorizedGw2ApiPermissions)) {
                        final String gw2ApiToken = authorizedRootToken.gw2ApiToken();

                        batch.add(() -> this.gw2APIService.createSubToken(gw2ApiToken, authorizedGw2ApiPermissions, expirationTime), (accumulator, context) -> {
                            try {
                                accumulator.put(gw2AccountId, new Pair<>(authorizedRootToken, context.get()));
                            } catch (ExecutionException | TimeoutException e) {
                                accumulator.put(gw2AccountId, new Pair<>(authorizedRootToken, null));
                            } catch (InterruptedException e) {
                                Thread.currentThread().interrupt();
                                accumulator.put(gw2AccountId, new Pair<>(authorizedRootToken, null));
                            }

                            return accumulator;
                        });
                    } else {
                        logging.log("The Root-API-Token named '%s' has less permissions than the authorization", displayName);
                    }
                }

                if (hasGw2AuthVerifiedScope) {
                    final boolean isVerified = verifiedGw2AccountIds.contains(gw2AccountId);
                    tokenForJWT.put("verified", isVerified);

                    logging.log("Including verified=%s for the Root-API-Token named '%s'", isVerified, displayName);
                }

                tokensForJWT.put(gw2AccountId, tokenForJWT);
            }

            final Map<String, Pair<ApiToken, Gw2SubToken>> result = batch.build().execute(this.gw2ApiClientExecutorService, HashMap::new, 10L, TimeUnit.SECONDS);

            for (Map.Entry<String, Pair<ApiToken, Gw2SubToken>> entry : result.entrySet()) {
                final String gw2AccountId = entry.getKey();
                final Map<String, Object> tokenForJWT = tokensForJWT.get(gw2AccountId);
                final String displayName = entry.getValue().v1().displayName();
                final Gw2SubToken gw2SubToken = entry.getValue().v2();

                if (gw2SubToken != null) {
                    if (gw2SubToken.permissions().equals(authorizedGw2ApiPermissions)) {
                        this.apiSubTokenRepository.save(new ApiSubTokenEntity(accountId, gw2AccountId, gw2ApiPermissionsBitSet, gw2SubToken.value(), expirationTime));

                        tokenForJWT.put("token", gw2SubToken.value());
                        logging.log("Added Subtoken for the Root-API-Token named '%s'", displayName);
                    } else {
                        tokenForJWT.put("error", "Failed to obtain new subtoken");
                        logging.log("The retrieved Subtoken for the Root-API-Token named '%s' appears to have less permissions than the authorization", displayName);
                    }
                } else {
                    tokenForJWT.put("error", "Failed to obtain new subtoken");
                    logging.log("Failed to retrieve a new Subtoken for the Root-API-Token named '%s' from the GW2-API", displayName);
                }
            }

            customize(ctx, clientConsent.accountSub(), authorizedGw2ApiPermissions, tokensForJWT);
        }
    }

    private void customize(JwtEncodingContext ctx, UUID accountSub, Set<Gw2ApiPermission> authorizedGw2ApiPermissions, Map<String, Map<String, Object>> tokensForJWT) {
        final List<String> permissionsForJWT = authorizedGw2ApiPermissions.stream()
                .map(Gw2ApiPermission::gw2)
                .collect(Collectors.toList());

        ctx.getClaims()
                .subject(accountSub.toString())
                .claim("gw2:permissions", permissionsForJWT)
                .claim("gw2:tokens", tokensForJWT);
    }
}
