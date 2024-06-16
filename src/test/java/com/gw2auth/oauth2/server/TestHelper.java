package com.gw2auth.oauth2.server;

import com.gw2auth.oauth2.server.repository.account.AccountEntity;
import com.gw2auth.oauth2.server.repository.account.AccountRepository;
import com.gw2auth.oauth2.server.repository.gw2account.Gw2AccountEntity;
import com.gw2auth.oauth2.server.repository.gw2account.Gw2AccountRepository;
import com.gw2auth.oauth2.server.repository.gw2account.apitoken.Gw2AccountApiTokenEntity;
import com.gw2auth.oauth2.server.repository.gw2account.apitoken.Gw2AccountApiTokenRepository;
import com.gw2auth.oauth2.server.repository.gw2account.verification.Gw2AccountVerificationEntity;
import com.gw2auth.oauth2.server.repository.gw2account.verification.Gw2AccountVerificationRepository;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.account.Account;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.account.AccountSession;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.oauth2.jwt.Jwt;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

@TestComponent
public class TestHelper {

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private Gw2AccountRepository gw2AccountRepository;

    @Autowired
    private Gw2AccountApiTokenRepository gw2AccountApiTokenRepository;

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

    public Pair<Gw2AccountEntity, Gw2AccountApiTokenEntity> createApiToken(UUID accountId, UUID gw2AccountId, Set<Gw2ApiPermission> gw2ApiPermissions, String name) {
        return createApiToken(accountId, gw2AccountId, randomRootToken(), gw2ApiPermissions, name);
    }

    public Pair<Gw2AccountEntity, Gw2AccountApiTokenEntity> createApiToken(UUID accountId, UUID gw2AccountId, String gw2ApiToken, Set<Gw2ApiPermission> gw2ApiPermissions, String name) {
        return createApiToken(accountId, gw2AccountId, gw2ApiToken, gw2ApiPermissions, name + ".1234", name);
    }

    public Pair<Gw2AccountEntity, Gw2AccountApiTokenEntity> createApiToken(UUID accountId, UUID gw2AccountId, String gw2ApiToken, Set<Gw2ApiPermission> gw2ApiPermissions, String name, String displayName) {
        final Instant now = Instant.now();
        final Gw2AccountEntity gw2AccountEntity = getOrCreateGw2Account(accountId, gw2AccountId, name, displayName);

        final Gw2AccountApiTokenEntity gw2AccountApiTokenEntity = this.gw2AccountApiTokenRepository.save(new Gw2AccountApiTokenEntity(
                accountId,
                gw2AccountId,
                now,
                gw2ApiToken,
                Gw2ApiPermission.toBitSet(gw2ApiPermissions),
                now,
                now
        ));

        return new Pair<>(gw2AccountEntity, gw2AccountApiTokenEntity);
    }

    public AccountEntity createAccount() {
        return this.accountRepository.save(new AccountEntity(
                UUID.randomUUID(),
                Instant.now()
        ));
    }

    public Gw2AccountEntity getOrCreateGw2Account(UUID accountId, UUID gw2AccountId) {
        return getOrCreateGw2Account(accountId, gw2AccountId, "Name.1234", "Name");
    }

    public Gw2AccountEntity getOrCreateGw2Account(UUID accountId, UUID gw2AccountId, String name, String displayName) {
        Instant now = Instant.now();

        return this.gw2AccountRepository.save(
                accountId,
                gw2AccountId,
                name,
                now,
                now,
                displayName,
                "A",
                null,
                null
        );
    }

    public Gw2AccountVerificationEntity createAccountVerification(UUID accountId, UUID gw2AccountId) {
        getOrCreateGw2Account(accountId, gw2AccountId);
        return this.gw2AccountVerificationRepository.save(gw2AccountId, accountId);
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
