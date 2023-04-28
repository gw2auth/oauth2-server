package com.gw2auth.oauth2.server;

import com.gw2auth.oauth2.server.repository.account.*;
import com.gw2auth.oauth2.server.repository.application.ApplicationEntity;
import com.gw2auth.oauth2.server.repository.application.ApplicationRepository;
import com.gw2auth.oauth2.server.repository.application.account.ApplicationAccountRepository;
import com.gw2auth.oauth2.server.repository.application.account.ApplicationAccountSubEntity;
import com.gw2auth.oauth2.server.repository.application.account.ApplicationAccountSubRepository;
import com.gw2auth.oauth2.server.repository.application.client.ApplicationClientEntity;
import com.gw2auth.oauth2.server.repository.application.client.ApplicationClientRepository;
import com.gw2auth.oauth2.server.repository.application.client.account.ApplicationClientAccountEntity;
import com.gw2auth.oauth2.server.repository.application.client.account.ApplicationClientAccountRepository;
import com.gw2auth.oauth2.server.repository.application.client.authorization.ApplicationClientAuthorizationEntity;
import com.gw2auth.oauth2.server.repository.application.client.authorization.ApplicationClientAuthorizationRepository;
import com.gw2auth.oauth2.server.repository.application.client.authorization.ApplicationClientAuthorizationTokenEntity;
import com.gw2auth.oauth2.server.repository.application.client.authorization.ApplicationClientAuthorizationTokenRepository;
import com.gw2auth.oauth2.server.repository.gw2account.Gw2AccountEntity;
import com.gw2auth.oauth2.server.repository.gw2account.Gw2AccountRepository;
import com.gw2auth.oauth2.server.repository.gw2account.apitoken.Gw2AccountApiTokenEntity;
import com.gw2auth.oauth2.server.repository.gw2account.apitoken.Gw2AccountApiTokenRepository;
import com.gw2auth.oauth2.server.repository.gw2account.apitoken.Gw2AccountApiTokenWithPreferencesEntity;
import com.gw2auth.oauth2.server.repository.gw2account.verification.Gw2AccountVerificationEntity;
import com.gw2auth.oauth2.server.repository.gw2account.verification.Gw2AccountVerificationRepository;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.account.Account;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.account.AccountSession;
import com.gw2auth.oauth2.server.service.application.client.account.ApplicationClientAccount;
import com.gw2auth.oauth2.server.service.security.Gw2AuthInternalJwtConverter;
import com.gw2auth.oauth2.server.service.security.SessionMetadata;
import com.gw2auth.oauth2.server.service.security.SessionMetadataService;
import com.gw2auth.oauth2.server.util.Constants;
import com.gw2auth.oauth2.server.util.Pair;
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

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@TestComponent
public class TestHelper {

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private AccountFederationRepository accountFederationRepository;

    @Autowired
    private Gw2AccountRepository gw2AccountRepository;

    @Autowired
    private Gw2AccountApiTokenRepository gw2AccountApiTokenRepository;

    @Autowired
    private ApplicationRepository applicationRepository;

    @Autowired
    private ApplicationClientRepository applicationClientRepository;

    @Autowired
    private ApplicationAccountSubRepository applicationAccountSubRepository;

    @Autowired
    private ApplicationAccountRepository applicationAccountRepository;

    @Autowired
    private ApplicationClientAccountRepository applicationClientAccountRepository;

    @Autowired
    private AccountLogRepository accountLogRepository;

    @Autowired
    private ApplicationClientAuthorizationRepository applicationClientAuthorizationRepository;

    @Autowired
    private ApplicationClientAuthorizationTokenRepository applicationClientAuthorizationTokenRepository;

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

    public Gw2AccountApiTokenWithPreferencesEntity createApiToken(UUID accountId, UUID gw2AccountId, Set<Gw2ApiPermission> gw2ApiPermissions, String name) {
        return createApiToken(accountId, gw2AccountId, randomRootToken(), gw2ApiPermissions, name);
    }

    public Gw2AccountApiTokenWithPreferencesEntity createApiToken(UUID accountId, UUID gw2AccountId, String gw2ApiToken, Set<Gw2ApiPermission> gw2ApiPermissions, String name) {
        final Instant now = Instant.now();
        final Gw2AccountEntity gw2AccountEntity = this.gw2AccountRepository.save(new Gw2AccountEntity(
                accountId,
                gw2AccountId,
                now,
                name,
                "A"
        ));

        final Gw2AccountApiTokenEntity gw2AccountApiTokenEntity = this.gw2AccountApiTokenRepository.save(new Gw2AccountApiTokenEntity(
                accountId,
                gw2AccountId,
                now,
                gw2ApiToken,
                Gw2ApiPermission.toBitSet(gw2ApiPermissions),
                now,
                now
        ));

        return new Gw2AccountApiTokenWithPreferencesEntity(
                gw2AccountApiTokenEntity.accountId(),
                gw2AccountApiTokenEntity.gw2AccountId(),
                gw2AccountApiTokenEntity.creationTime(),
                gw2AccountApiTokenEntity.gw2ApiToken(),
                gw2AccountApiTokenEntity.gw2ApiPermissionsBitSet(),
                gw2AccountApiTokenEntity.lastValidTime(),
                gw2AccountApiTokenEntity.lastValidCheckTime(),
                gw2AccountEntity.displayName(),
                gw2AccountEntity.orderRank()
        );
    }

    public ApplicationClientEntity createClientRegistration(UUID accountId, String name) {
        return createClientRegistration(accountId, name, Set.of("http://test.gw2auth.com/dummy"));
    }

    public ApplicationClientEntity createClientRegistration(UUID accountId, String name, Set<String> redirectUris) {
        final ApplicationEntity applicationEntity = this.applicationRepository.save(new ApplicationEntity(
                UUID.randomUUID(),
                accountId,
                Instant.now(),
                name
        ));

        return this.applicationClientRepository.save(new ApplicationClientEntity(
                UUID.randomUUID(),
                applicationEntity.id(),
                Instant.now(),
                name,
                UUID.randomUUID().toString(),
                Set.of(AuthorizationGrantType.AUTHORIZATION_CODE.getValue(), AuthorizationGrantType.REFRESH_TOKEN.getValue()),
                redirectUris,
                false
        ));
    }

    public ApplicationClientAccountEntity createClientConsent(UUID accountId, UUID clientRegistrationId, Set<String> scopes) {
        return createClientConsent2(accountId, clientRegistrationId, scopes).v2();
    }

    public Pair<UUID, ApplicationClientAccountEntity> createClientConsent2(UUID accountId, UUID clientRegistrationId, Set<String> scopes) {
        final UUID applicationId = this.applicationClientRepository.findById(clientRegistrationId).orElseThrow().applicationId();

        final ApplicationAccountSubEntity applicationAccountSubEntity = this.applicationAccountSubRepository.findOrCreate(
                applicationId,
                accountId,
                UUID.randomUUID()
        );
        this.applicationAccountRepository.findOrCreate(
                applicationId,
                accountId,
                Instant.now()
        );
        final ApplicationClientAccountEntity applicationClientAccountEntity =  this.applicationClientAccountRepository.save(new ApplicationClientAccountEntity(
                clientRegistrationId,
                accountId,
                applicationId,
                ApplicationClientAccount.ApprovalStatus.APPROVED.name(),
                "UNIT-TEST",
                scopes
        ));

        return new Pair<>(applicationAccountSubEntity.accountSub(), applicationClientAccountEntity);
    }

    public AccountEntity createAccount() {
        return this.accountRepository.save(new AccountEntity(
                UUID.randomUUID(),
                Instant.now()
        ));
    }

    public AccountFederationEntity createAccountFederation(String issuer, String idAtIssuer, UUID accountId) {
        return this.accountFederationRepository.save(new AccountFederationEntity(
                issuer,
                idAtIssuer,
                accountId
        ));
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

    public ApplicationClientAuthorizationEntity createClientAuthorization(UUID accountId, UUID clientRegistrationId, Set<String> scopes) {
        return createClientAuthorization(accountId, clientRegistrationId, Instant.now(), scopes, false);
    }

    public ApplicationClientAuthorizationEntity createClientAuthorization(UUID accountId, UUID clientRegistrationId, Instant creationTime, Set<String> scopes, boolean fillTokens) {
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

        return this.applicationClientAuthorizationRepository.save(new ApplicationClientAuthorizationEntity(
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

    public ApplicationClientAuthorizationTokenEntity createClientAuthorizationToken(UUID accountId, String clientAuthorizationId, UUID gw2AccountId) {
        return this.applicationClientAuthorizationTokenRepository.save(new ApplicationClientAuthorizationTokenEntity(clientAuthorizationId, accountId, gw2AccountId));
    }

    public List<ApplicationClientAuthorizationTokenEntity> createClientAuthorizationTokens(UUID accountId, String clientAuthorizationId, UUID... gw2AccountIds) {
        return createClientAuthorizationTokens(accountId, clientAuthorizationId, List.of(gw2AccountIds));
    }

    public List<ApplicationClientAuthorizationTokenEntity> createClientAuthorizationTokens(UUID accountId, String clientAuthorizationId, Collection<UUID> gw2AccountIds) {
        return gw2AccountIds.stream()
                .map((gw2AccountId) -> createClientAuthorizationToken(accountId, clientAuthorizationId, gw2AccountId))
                .collect(Collectors.toList());
    }

    public Gw2AccountEntity getOrCreateGw2Account(UUID accountId, UUID gw2AccountId) {
        return this.gw2AccountRepository.save(
                accountId,
                gw2AccountId,
                Instant.now(),
                "Name",
                "A",
                null,
                null
        );
    }

    public Gw2AccountVerificationEntity createAccountVerification(UUID accountId, UUID gw2AccountId) {
        getOrCreateGw2Account(accountId, gw2AccountId);
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
                .map(AccountSession::metadata)
                .map((metadata) -> {
                    final Pair<SecretKey, IvParameterSpec> pair = SymEncryption.fromBytes(this.jwtConverter.readEncryptionKey(jwt));
                    return this.sessionMetadataService.decryptMetadata(pair.v1(), pair.v2(), metadata);
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
