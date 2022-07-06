package com.gw2auth.oauth2.server;

import com.gw2auth.oauth2.server.adapt.Gw2AuthInternalJwtConverter;
import com.gw2auth.oauth2.server.repository.apitoken.ApiTokenEntity;
import com.gw2auth.oauth2.server.repository.apitoken.ApiTokenRepository;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationEntity;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationRepository;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationTokenEntity;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationTokenRepository;
import com.gw2auth.oauth2.server.repository.client.consent.ClientConsentEntity;
import com.gw2auth.oauth2.server.repository.client.consent.ClientConsentLogEntity;
import com.gw2auth.oauth2.server.repository.client.consent.ClientConsentLogRepository;
import com.gw2auth.oauth2.server.repository.client.consent.ClientConsentRepository;
import com.gw2auth.oauth2.server.repository.client.registration.ClientRegistrationEntity;
import com.gw2auth.oauth2.server.repository.client.registration.ClientRegistrationRepository;
import com.gw2auth.oauth2.server.repository.verification.Gw2AccountVerificationEntity;
import com.gw2auth.oauth2.server.repository.verification.Gw2AccountVerificationRepository;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.user.Gw2AuthTokenUserService;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUserV2;
import com.gw2auth.oauth2.server.util.Constants;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import javax.servlet.http.Cookie;
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
    private ClientConsentLogRepository clientConsentLogRepository;

    @Autowired
    private ClientAuthorizationRepository clientAuthorizationRepository;

    @Autowired
    private ClientAuthorizationTokenRepository clientAuthorizationTokenRepository;

    @Autowired
    private Gw2AccountVerificationRepository gw2AccountVerificationRepository;

    @Autowired
    private Gw2AuthInternalJwtConverter jwtConverter;

    @Autowired
    private Gw2AuthTokenUserService gw2AuthTokenUserService;

    @Autowired
    private JdbcOperations jdbcOperations;

    public static String randomRootToken() {
        return (UUID.randomUUID() + UUID.randomUUID().toString()).toUpperCase();
    }

    public static String createSubtokenJWT(UUID sub, Set<Gw2ApiPermission> permissions, Instant issuedAt, Duration expiresIn) {
        final JSONArray jsonPermissions = new JSONArray();
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

    public ApiTokenEntity createApiToken(long accountId, UUID gw2AccountId, Set<Gw2ApiPermission> gw2ApiPermissions, String name) {
        return createApiToken(accountId, gw2AccountId, randomRootToken(), gw2ApiPermissions, name);
    }

    public ApiTokenEntity createApiToken(long accountId, UUID gw2AccountId, String gw2ApiToken, Set<Gw2ApiPermission> gw2ApiPermissions, String name) {
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

    public ClientRegistrationEntity createClientRegistration(long accountId, String name) {
        return this.clientRegistrationRepository.save(new ClientRegistrationEntity(
                null,
                accountId,
                Instant.now(),
                name,
                UUID.randomUUID(),
                UUID.randomUUID().toString(),
                Set.of(AuthorizationGrantType.AUTHORIZATION_CODE.getValue(), AuthorizationGrantType.REFRESH_TOKEN.getValue()),
                Set.of("http://test.gw2auth.com/dummy")
        ));
    }

    public ClientConsentEntity createClientConsent(long accountId, long clientRegistrationId, Set<String> scopes) {
        return this.clientConsentRepository.save(new ClientConsentEntity(accountId, clientRegistrationId, UUID.randomUUID(), scopes));
    }

    public ClientConsentLogEntity createClientLog(long accountId, long clientRegistrationId, String type, List<String> messages) {
        return this.clientConsentLogRepository.save(new ClientConsentLogEntity(
                null,
                accountId,
                clientRegistrationId,
                Instant.now(),
                type,
                messages
        ));
    }

    public ClientAuthorizationEntity createClientAuthorization(long accountId, long clientRegistrationId, Set<String> scopes) {
        final Instant now = Instant.now();

        return this.clientAuthorizationRepository.save(new ClientAuthorizationEntity(
                accountId,
                UUID.randomUUID().toString(),
                clientRegistrationId,
                now,
                now,
                "Name",
                AuthorizationGrantType.JWT_BEARER.getValue(),
                scopes,
                "",
                UUID.randomUUID().toString(),
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                scopes,
                null,
                null,
                null,
                null
        ));
    }

    public ClientAuthorizationTokenEntity createClientAuthorizationToken(long accountId, String clientAuthorizationId, UUID gw2AccountId) {
        return this.clientAuthorizationTokenRepository.save(new ClientAuthorizationTokenEntity(accountId, clientAuthorizationId, gw2AccountId));
    }

    public List<ClientAuthorizationTokenEntity> createClientAuthorizationTokens(long accountId, String clientAuthorizationId, UUID... gw2AccountIds) {
        return Arrays.stream(gw2AccountIds)
                .map((gw2AccountId) -> createClientAuthorizationToken(accountId, clientAuthorizationId, gw2AccountId))
                .collect(Collectors.toList());
    }

    public Gw2AccountVerificationEntity createAccountVerification(long accountId, UUID gw2AccountId) {
        return this.gw2AccountVerificationRepository.save(new Gw2AccountVerificationEntity(gw2AccountId, accountId));
    }

    public Optional<String> getSessionIdForCookie(CookieHolder cookieHolder) {
        final Cookie cookie = cookieHolder.getCookie(Constants.ACCESS_TOKEN_COOKIE_NAME);

        if (cookie == null || cookie.getMaxAge() <= 0 || cookie.getValue().isEmpty()) {
            return Optional.empty();
        }

        return Optional.of(this.jwtConverter.readSessionId(this.jwtConverter.readJWT(cookie.getValue())));
    }

    public OptionalLong getAccountIdForCookie(CookieHolder cookieHolder) {
        final Cookie cookie = cookieHolder.getCookie(Constants.ACCESS_TOKEN_COOKIE_NAME);

        if (cookie == null || cookie.getMaxAge() <= 0 || cookie.getValue().isEmpty()) {
            return OptionalLong.empty();
        }

        return this.gw2AuthTokenUserService.resolveUserForToken(cookie.getValue())
                .map(Gw2AuthUserV2::getAccountId)
                .map(OptionalLong::of)
                .orElseGet(OptionalLong::empty);
    }

    public int executeUpdate(String sql, Object... args) {
        return this.jdbcOperations.update(sql, args);
    }
}
