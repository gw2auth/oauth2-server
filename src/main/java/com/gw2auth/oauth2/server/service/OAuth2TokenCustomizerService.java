package com.gw2auth.oauth2.server.service;

import com.gw2auth.oauth2.server.service.apitoken.ApiToken;
import com.gw2auth.oauth2.server.service.apitoken.ApiTokenService;
import com.gw2auth.oauth2.server.service.client.authorization.ClientAuthorization;
import com.gw2auth.oauth2.server.service.client.authorization.ClientAuthorizationService;
import com.gw2auth.oauth2.server.service.gw2.Gw2ApiService;
import com.gw2auth.oauth2.server.service.gw2.Gw2ApiServiceException;
import com.gw2auth.oauth2.server.service.gw2.Gw2SubToken;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUser;
import com.gw2auth.oauth2.server.service.verification.VerificationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class OAuth2TokenCustomizerService implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private static final Duration AUTHORIZED_TOKEN_MIN_EXCESS_TIME = Duration.ofMinutes(20L);

    private final ApiTokenService apiTokenService;
    private final ClientAuthorizationService clientAuthorizationService;
    private final VerificationService verificationService;
    private final Gw2ApiService gw2APIService;
    private volatile Clock clock;

    @Autowired
    public OAuth2TokenCustomizerService(ApiTokenService apiTokenService, ClientAuthorizationService clientAuthorizationService, VerificationService verificationService, Gw2ApiService gw2APIService) {
        this.apiTokenService = apiTokenService;
        this.clientAuthorizationService = clientAuthorizationService;
        this.verificationService = verificationService;
        this.gw2APIService = gw2APIService;
        this.clock = Clock.systemDefaultZone();
    }

    public void setClock(Clock clock) {
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    @Transactional
    public void customize(JwtEncodingContext ctx) {
        if (ctx.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
            final RegisteredClient registeredClient = ctx.getRegisteredClient();// the client of the application the user wants to access
            final OAuth2AuthenticationToken auth = ctx.getPrincipal();
            final OAuth2User oAuth2User = auth.getPrincipal();// the user

            if (oAuth2User instanceof Gw2AuthUser) {
                final long accountId = ((Gw2AuthUser) oAuth2User).getAccountId();
                final long clientRegistrationId = Long.parseLong(registeredClient.getId());

                customize(ctx, accountId, clientRegistrationId);
            } else {
                throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR));
            }
        }
    }

    private void customize(JwtEncodingContext ctx, long accountId, long clientRegistrationId) {
        final ClientAuthorization clientAuthorization = this.clientAuthorizationService.getClientAuthorization(accountId, clientRegistrationId).orElseThrow(() -> new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED)));

        try (ClientAuthorizationService.LoggingContext logging = this.clientAuthorizationService.log(accountId, clientRegistrationId, ClientAuthorizationService.LogType.ACCESS_TOKEN)) {
            final Set<Gw2ApiPermission> authorizedGw2ApiPermissions = clientAuthorization.authorizedScopes()
                    .stream()
                    .flatMap((scope) -> Gw2ApiPermission.fromOAuth2(scope).stream())
                    .collect(Collectors.toSet());

            if (authorizedGw2ApiPermissions.isEmpty() || clientAuthorization.tokens().isEmpty()) {
                logging.log("The Consent has been removed: responding with ACCESS_DENIED");
                throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED));
            }

            final Map<String, ClientAuthorization.Token> authorizedTokens = clientAuthorization.tokens();
            final List<ApiToken> authorizedRootTokens = this.apiTokenService.getApiTokens(accountId, authorizedTokens.keySet());

            // in theory, this should not happen since authorized-tokens and root-tokens are related via foreign key
            if (authorizedRootTokens.isEmpty()) {
                logging.log("All linked Root-API-Tokens have been removed: responding with ACCESS_DENIED");
                throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED));
            }

            final Set<String> verifiedGw2AccountIds;
            final boolean hasGw2AuthVerifiedScope = clientAuthorization.authorizedScopes().contains(ClientAuthorizationService.GW2AUTH_VERIFIED_SCOPE);

            if (hasGw2AuthVerifiedScope) {
                verifiedGw2AccountIds = this.verificationService.getVerifiedGw2AccountIds(accountId);
            } else {
                verifiedGw2AccountIds = Set.of();
            }

            final Instant minExpirationTime = getMinExpirationTime(authorizedTokens);
            final Map<String, Map<String, Object>> tokensForJWT = new HashMap<>(authorizedTokens.size());

            // check if all authorized tokens are still valid for at least the configured amount of time
            // if so, dont request new subtokens from the gw2 api but just respond with the existing ones
            if (minExpirationTime.isAfter(this.clock.instant().plus(AUTHORIZED_TOKEN_MIN_EXCESS_TIME))) {
                ctx.getClaims().expiresAt(minExpirationTime);

                logging.log("All existing Subtokens are still valid; Adding existing Subtokens to Access-Token");

                for (ApiToken authorizedRootToken : authorizedRootTokens) {
                    final String gw2AccountId = authorizedRootToken.gw2AccountId();
                    final String displayName = authorizedRootToken.displayName();
                    final String gw2ApiSubtoken = authorizedTokens.get(gw2AccountId).gw2ApiSubtoken();
                    final Map<String, Object> tokenForJWT = new LinkedHashMap<>(3);

                    tokenForJWT.put("name", displayName);
                    tokenForJWT.put("token", gw2ApiSubtoken);

                    if (hasGw2AuthVerifiedScope) {
                        final boolean isVerified = verifiedGw2AccountIds.contains(gw2AccountId);
                        tokenForJWT.put("verified", isVerified);

                        logging.log("Added existing Subtoken for the Root-API-Token named '%s' including verified=%s", displayName, isVerified);
                    } else {
                        logging.log("Added existing Subtoken for the Root-API-Token named '%s'", displayName);
                    }

                    tokensForJWT.put(gw2AccountId, tokenForJWT);
                }
            } else {
                final Instant expiresAt = ctx.getClaims().build().getExpiresAt();
                final Map<String, ClientAuthorization.Token> updatedAuthorizedTokens = updateTokens(authorizedGw2ApiPermissions, authorizedRootTokens, verifiedGw2AccountIds, hasGw2AuthVerifiedScope, tokensForJWT, expiresAt, logging);

                this.clientAuthorizationService.updateTokens(accountId, clientRegistrationId, updatedAuthorizedTokens);
            }

            customize(ctx, clientAuthorization.accountSub(), authorizedGw2ApiPermissions, tokensForJWT);
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

    private Map<String, ClientAuthorization.Token> updateTokens(Set<Gw2ApiPermission> authorizedGw2ApiPermissions,
                                                                List<ApiToken> authorizedRootTokens,
                                                                Set<String> verifiedGw2AccountIds,
                                                                boolean hasGw2AuthVerifiedScope,
                                                                Map<String, Map<String, Object>> tokensForJWT,
                                                                Instant expiresAt,
                                                                ClientAuthorizationService.LoggingContext logging) {

        final Map<String, ClientAuthorization.Token> updatedAuthorizedTokens = new HashMap<>(authorizedRootTokens.size());

        for (ApiToken authorizedRootToken : authorizedRootTokens) {
            final String gw2AccountId = authorizedRootToken.gw2AccountId();
            final String displayName = authorizedRootToken.displayName();

            final Map<String, Object> tokenForJWT = new LinkedHashMap<>(3);
            tokenForJWT.put("name", displayName);

            if (authorizedRootToken.gw2ApiPermissions().containsAll(authorizedGw2ApiPermissions)) {
                Gw2SubToken subToken = null;
                try {
                    subToken = this.gw2APIService.createSubToken(authorizedRootToken.gw2ApiToken(), authorizedGw2ApiPermissions, expiresAt);
                } catch (Gw2ApiServiceException e) {
                    logging.log("Failed to retrieve a new Subtoken for the Root-API-Token named '%s' from the GW2-API", displayName);
                }

                if (subToken != null) {
                    if (subToken.permissions().containsAll(authorizedGw2ApiPermissions)) {
                        updatedAuthorizedTokens.put(gw2AccountId, new ClientAuthorization.Token(subToken.value(), expiresAt));
                        tokenForJWT.put("token", subToken.value());
                        logging.log("Added Subtoken for the Root-API-Token named '%s'", displayName);
                    } else {
                        logging.log("The retrieved Subtoken for the Root-API-Token named '%s' appears to have less permissions than the authorization", displayName);
                    }
                }
            } else {
                logging.log("The Root-API-Token named '%s' has less permissions than the authorization", displayName);
            }

            if (!tokenForJWT.containsKey("token")) {
                tokenForJWT.put("error", "Failed to obtain new subtoken");
            }

            if (hasGw2AuthVerifiedScope) {
                final boolean isVerified = verifiedGw2AccountIds.contains(gw2AccountId);
                tokenForJWT.put("verified", isVerified);

                logging.log("Including verified=%s information for the Root-API-Token named '%s'", isVerified, displayName);
            }

            tokensForJWT.put(gw2AccountId, tokenForJWT);
        }

        return updatedAuthorizedTokens;
    }

    private Instant getMinExpirationTime(Map<String, ClientAuthorization.Token> tokens) {
        return tokens.values().stream()
                .map(ClientAuthorization.Token::expirationTime)
                .min(Comparator.naturalOrder())
                .orElse(Instant.MIN);
    }
}
