package com.gw2auth.oauth2.server;

import com.gw2auth.oauth2.server.repository.account.AccountLogEntity;
import com.gw2auth.oauth2.server.repository.account.AccountLogRepository;
import com.gw2auth.oauth2.server.repository.apitoken.ApiTokenEntity;
import com.gw2auth.oauth2.server.repository.apitoken.ApiTokenRepository;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationEntity;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationRepository;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationTokenEntity;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationTokenRepository;
import com.gw2auth.oauth2.server.repository.client.consent.ClientConsentEntity;
import com.gw2auth.oauth2.server.repository.client.consent.ClientConsentRepository;
import com.gw2auth.oauth2.server.repository.client.registration.ClientRegistrationEntity;
import com.gw2auth.oauth2.server.repository.client.registration.ClientRegistrationRepository;
import com.gw2auth.oauth2.server.repository.verification.Gw2AccountVerificationEntity;
import com.gw2auth.oauth2.server.repository.verification.Gw2AccountVerificationRepository;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.account.Account;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.account.AccountSession;
import com.gw2auth.oauth2.server.service.security.Gw2AuthInternalJwtConverter;
import com.gw2auth.oauth2.server.service.security.SessionMetadata;
import com.gw2auth.oauth2.server.service.security.SessionMetadataService;
import com.gw2auth.oauth2.server.util.Constants;
import com.gw2auth.oauth2.server.util.SymEncryption;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.Cookie;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@TestComponent
public class TestHelper {

    @Autowired
    private ApiTokenRepository apiTokenRepository;

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Autowired
    private ClientConsentRepository clientConsentRepository;

    @Autowired
    private AccountLogRepository accountLogRepository;

    @Autowired
    private ClientAuthorizationRepository clientAuthorizationRepository;

    @Autowired
    private ClientAuthorizationTokenRepository clientAuthorizationTokenRepository;

    @Autowired
    private Gw2AccountVerificationRepository gw2AccountVerificationRepository;

    @Autowired
    private Gw2AuthInternalJwtConverter jwtConverter;

    @Autowired
    private SessionMetadataService sessionMetadataService;

    @Autowired
    private AccountService accountService;

    @Autowired
    private JdbcOperations jdbcOperations;

    public static String randomRootToken() {
        return (UUID.randomUUID() + UUID.randomUUID().toString()).toUpperCase();
    }

    public static String createSubtokenJWT(UUID sub, Set<Gw2ApiPermission> permissions, Instant issuedAt, Duration expiresIn) {
        final List<String> jsonPermissions = new ArrayList<>();
        permissions.stream().map(Gw2ApiPermission::gw2).forEach(jsonPermissions::add);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(sub.toString())
                .jwtID(UUID.randomUUID().toString())
                .issueTime(new Date(issuedAt.toEpochMilli()))
                .expirationTime(new Date(issuedAt.plus(expiresIn).toEpochMilli()))
                .claim("permissions", jsonPermissions)
                .build();

        final SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256, JOSEObjectType.JWT, null, null, null, null, null, null, null, null, null, true,null, null), claims);
        try {
            signedJWT.sign(new MACSigner(new byte[32]));
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        return signedJWT.serialize();
    }

    public static <T> Optional<? extends T> first(Collection<? extends T> collection) {
        return collection.stream().findFirst();
    }

    public ApiTokenEntity createApiToken(UUID accountId, UUID gw2AccountId, Set<Gw2ApiPermission> gw2ApiPermissions, String name) {
        return createApiToken(accountId, gw2AccountId, randomRootToken(), gw2ApiPermissions, name);
    }

    public ApiTokenEntity createApiToken(UUID accountId, UUID gw2AccountId, String gw2ApiToken, Set<Gw2ApiPermission> gw2ApiPermissions, String name) {
        final Instant now = Instant.now();
        return this.apiTokenRepository.save(new ApiTokenEntity(
                accountId,
                gw2AccountId,
                now,
                gw2ApiToken,
                gw2ApiPermissions.stream().map(Gw2ApiPermission::gw2).collect(Collectors.toSet()),
                now,
                true,
                name
        ));
    }

    public ClientRegistrationEntity createClientRegistration(UUID accountId, String name) {
        return this.clientRegistrationRepository.save(new ClientRegistrationEntity(
                UUID.randomUUID(),
                accountId,
                Instant.now(),
                name,
                UUID.randomUUID().toString(),
                Set.of(AuthorizationGrantType.AUTHORIZATION_CODE.getValue(), AuthorizationGrantType.REFRESH_TOKEN.getValue()),
                Set.of("http://test.gw2auth.com/dummy")
        ));
    }

    public ClientConsentEntity createClientConsent(UUID accountId, UUID clientRegistrationId, Set<String> scopes) {
        return this.clientConsentRepository.save(new ClientConsentEntity(accountId, clientRegistrationId, UUID.randomUUID(), scopes));
    }

    public AccountLogEntity createAccountLog(UUID accountId, String message, Map<String, ?> fields) {
        return this.accountLogRepository.save(new AccountLogEntity(
                UUID.randomUUID(),
                accountId,
                Instant.now(),
                message,
                new JSONObject(fields),
                false
        ));
    }

    public ClientAuthorizationEntity createClientAuthorization(UUID accountId, UUID clientRegistrationId, Set<String> scopes) {
        return createClientAuthorization(accountId, clientRegistrationId, Instant.now(), scopes, false);
    }

    public ClientAuthorizationEntity createClientAuthorization(UUID accountId, UUID clientRegistrationId, Instant creationTime, Set<String> scopes, boolean fillTokens) {
        String authorizationCodeValue = null;
        Instant authorizationCodeIssuedAt = null;
        Instant authorizationCodeExpiresAt = null;
        String authorizationCodeMetadata = null;
        String accessTokenValue = null;
        Instant accessTokenIssuedAt = null;
        Instant accessTokenExpiresAt = null;
        String accessTokenMetadata = null;
        String accessTokenType = null;
        String refreshTokenValue = null;
        Instant refreshTokenIssuedAt = null;
        Instant refreshTokenExpiresAt = null;
        String refreshTokenMetadata = null;

        if (fillTokens) {
            authorizationCodeValue = UUID.randomUUID().toString();
            authorizationCodeIssuedAt = creationTime;
            authorizationCodeExpiresAt = creationTime.plus(Duration.ofMinutes(60L));
            authorizationCodeMetadata = "{}";
            accessTokenValue = UUID.randomUUID().toString();
            accessTokenIssuedAt = creationTime;
            accessTokenExpiresAt = creationTime.plus(Duration.ofMinutes(30L));
            accessTokenMetadata = "{}";
            accessTokenType = OAuth2AccessToken.TokenType.BEARER.getValue();
            refreshTokenValue = UUID.randomUUID().toString();
            refreshTokenIssuedAt = creationTime;
            refreshTokenExpiresAt = creationTime.plus(Duration.ofDays(180L));
            refreshTokenMetadata = "{}";
        }

        return this.clientAuthorizationRepository.save(new ClientAuthorizationEntity(
                UUID.randomUUID().toString(),
                accountId,
                clientRegistrationId,
                creationTime,
                creationTime,
                "Name",
                AuthorizationGrantType.JWT_BEARER.getValue(),
                scopes,
                "",
                UUID.randomUUID().toString(),
                authorizationCodeValue,
                authorizationCodeIssuedAt,
                authorizationCodeExpiresAt,
                authorizationCodeMetadata,
                accessTokenValue,
                accessTokenIssuedAt,
                accessTokenExpiresAt,
                accessTokenMetadata,
                accessTokenType,
                scopes,
                refreshTokenValue,
                refreshTokenIssuedAt,
                refreshTokenExpiresAt,
                refreshTokenMetadata
        ));
    }

    public ClientAuthorizationTokenEntity createClientAuthorizationToken(UUID accountId, String clientAuthorizationId, UUID gw2AccountId) {
        return this.clientAuthorizationTokenRepository.save(new ClientAuthorizationTokenEntity(clientAuthorizationId, accountId, gw2AccountId));
    }

    public List<ClientAuthorizationTokenEntity> createClientAuthorizationTokens(UUID accountId, String clientAuthorizationId, UUID... gw2AccountIds) {
        return createClientAuthorizationTokens(accountId, clientAuthorizationId, List.of(gw2AccountIds));
    }

    public List<ClientAuthorizationTokenEntity> createClientAuthorizationTokens(UUID accountId, String clientAuthorizationId, Collection<UUID> gw2AccountIds) {
        return gw2AccountIds.stream()
                .map((gw2AccountId) -> createClientAuthorizationToken(accountId, clientAuthorizationId, gw2AccountId))
                .collect(Collectors.toList());
    }

    public Gw2AccountVerificationEntity createAccountVerification(UUID accountId, UUID gw2AccountId) {
        return this.gw2AccountVerificationRepository.save(new Gw2AccountVerificationEntity(gw2AccountId, accountId));
    }

    public Optional<Jwt> getJwtForCookie(SessionHandle sessionHandle) {
        final Cookie cookie = sessionHandle.getCookie(Constants.ACCESS_TOKEN_COOKIE_NAME);

        if (cookie == null || cookie.getMaxAge() <= 0 || cookie.getValue().isEmpty()) {
            return Optional.empty();
        }

        return Optional.of(this.jwtConverter.readJWT(cookie.getValue()));
    }

    public String jwtToSessionId(Jwt jwt) {
        return this.jwtConverter.readSessionId(jwt);
    }

    public Optional<SessionMetadata> jwtToSessionMetadata(Jwt jwt) {
        return sessionIdToAccountSession(jwtToSessionId(jwt))
                .flatMap((session) -> Optional.ofNullable(session.metadata()))
                .flatMap((metadata) -> {
                    return this.jwtConverter.readEncryptionKey(jwt)
                            .map(SymEncryption::fromBytes)
                            .map((pair) -> this.sessionMetadataService.decryptMetadata(pair.v1(), pair.v2(), metadata));
                });
    }

    public Optional<AccountSession> sessionIdToAccountSession(String sessionId) {
        return this.accountService.getAccountForSession(sessionId);
    }

    public Optional<String> getSessionIdForCookie(SessionHandle sessionHandle) {
        return getJwtForCookie(sessionHandle).map(this::jwtToSessionId);
    }

    public Optional<UUID> getAccountIdForCookie(SessionHandle sessionHandle) {
        return getSessionIdForCookie(sessionHandle)
                .flatMap(this::sessionIdToAccountSession)
                .map(AccountSession::account)
                .map(Account::id);
    }

    public int executeUpdate(String sql, Object... args) {
        return this.jdbcOperations.update(sql, args);
    }
}
