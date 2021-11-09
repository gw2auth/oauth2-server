package com.gw2auth.oauth2.server;

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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestComponent;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

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

    public ApiTokenEntity createApiToken(long accountId, String gw2AccountId, Set<Gw2ApiPermission> gw2ApiPermissions, String name) {
        return this.apiTokenRepository.save(new ApiTokenEntity(
                accountId,
                gw2AccountId,
                Instant.now(),
                UUID.randomUUID().toString(),
                gw2ApiPermissions.stream().map(Gw2ApiPermission::gw2).collect(Collectors.toSet()),
                name
        ));
    }

    public ClientRegistrationEntity createClientRegistration(long accountId, String name) {
        return this.clientRegistrationRepository.save(new ClientRegistrationEntity(
                null,
                accountId,
                Instant.now(),
                name,
                UUID.randomUUID().toString(),
                UUID.randomUUID().toString(),
                Set.of(AuthorizationGrantType.AUTHORIZATION_CODE.getValue(), AuthorizationGrantType.REFRESH_TOKEN.getValue()),
                "http://test.gw2auth.com/dummy"
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

    public ClientAuthorizationTokenEntity createClientAuthorizationToken(long accountId, String clientAuthorizationId, String gw2AccountId) {
        return this.clientAuthorizationTokenRepository.save(new ClientAuthorizationTokenEntity(accountId, clientAuthorizationId, gw2AccountId));
    }

    public List<ClientAuthorizationTokenEntity> createClientAuthorizationTokens(long accountId, String clientAuthorizationId, String... gw2AccountIds) {
        return Arrays.stream(gw2AccountIds)
                .map((gw2AccountId) -> createClientAuthorizationToken(accountId, clientAuthorizationId, gw2AccountId))
                .collect(Collectors.toList());
    }

    public Gw2AccountVerificationEntity createAccountVerification(long accountId, String gw2AccountId) {
        return this.gw2AccountVerificationRepository.save(new Gw2AccountVerificationEntity(gw2AccountId, accountId));
    }
}
