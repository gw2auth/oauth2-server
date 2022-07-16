package com.gw2auth.oauth2.server.service.client.consent;

import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationEntity;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationRepository;
import com.gw2auth.oauth2.server.repository.client.consent.ClientConsentEntity;
import com.gw2auth.oauth2.server.repository.client.consent.ClientConsentRepository;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.client.AuthorizationCodeParamAccessor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.function.Predicate;
import java.util.stream.Collectors;

@Service
public class ClientConsentServiceImpl implements ClientConsentService, OAuth2AuthorizationConsentService {

    private final AccountService accountService;
    private final ClientConsentRepository clientConsentRepository;
    private final ClientAuthorizationRepository clientAuthorizationRepository;
    private final AuthorizationCodeParamAccessor authorizationCodeParamAccessor;

    public ClientConsentServiceImpl(AccountService accountService,
                                    ClientConsentRepository clientConsentRepository,
                                    ClientAuthorizationRepository clientAuthorizationRepository,
                                    AuthorizationCodeParamAccessor authorizationCodeParamAccessor) {

        this.accountService = accountService;
        this.clientConsentRepository = clientConsentRepository;
        this.clientAuthorizationRepository = clientAuthorizationRepository;
        this.authorizationCodeParamAccessor = authorizationCodeParamAccessor;
    }

    @Autowired
    public ClientConsentServiceImpl(AccountService accountService, ClientConsentRepository clientConsentRepository, ClientAuthorizationRepository clientAuthorizationRepository) {
        this(accountService, clientConsentRepository, clientAuthorizationRepository, AuthorizationCodeParamAccessor.DEFAULT);
    }

    @Override
    public List<ClientConsent> getClientConsents(UUID accountId) {
        return this.clientConsentRepository.findAllByAccountId(accountId).stream()
                .filter(ClientConsentServiceImpl::isAuthorized)
                .map(ClientConsent::fromEntity)
                .collect(Collectors.toList());
    }

    @Override
    public Optional<ClientConsent> getClientConsent(UUID accountId, UUID clientRegistrationId) {
        return this.clientConsentRepository.findByAccountIdAndClientRegistrationId(accountId, clientRegistrationId)
                .filter(ClientConsentServiceImpl::isAuthorized)
                .map(ClientConsent::fromEntity);
    }

    @Override
    @Transactional
    public void createEmptyClientConsentIfNotExists(UUID accountId, UUID clientRegistrationId) {
        final Optional<ClientConsentEntity> optional = this.clientConsentRepository.findByAccountIdAndClientRegistrationId(accountId, clientRegistrationId);
        if (optional.isEmpty()) {
            this.clientConsentRepository.save(createAuthorizedClientEntity(accountId, clientRegistrationId));
        }
    }

    @Override
    @Transactional
    public void deleteClientConsent(UUID accountId, UUID clientRegistrationId) {
        this.clientConsentRepository.findByAccountIdAndClientRegistrationId(accountId, clientRegistrationId).ifPresent(this::deleteInternal);
    }

    @Transactional
    protected void deleteInternal(ClientConsentEntity entity) {
        // not actually deleting, since we want to keep the client specific account sub
        this.clientConsentRepository.deleteByAccountIdAndClientRegistrationId(entity.accountId(), entity.clientRegistrationId());
        this.clientConsentRepository.save(new ClientConsentEntity(entity.accountId(), entity.clientRegistrationId(), entity.accountSub(), Set.of()));
    }

    // region OAuth2AuthorizationConsentService
    @Override
    @Transactional
    public void save(OAuth2AuthorizationConsent authorizationConsent) {
        if (!authorizationConsent.getScopes().containsAll(this.authorizationCodeParamAccessor.getRequestedScopes())) {
            throw this.authorizationCodeParamAccessor.error(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED));
        }

        final UUID accountId = UUID.fromString(authorizationConsent.getPrincipalName());
        final UUID clientRegistrationId = UUID.fromString(authorizationConsent.getRegisteredClientId());

        ClientConsentEntity clientConsentEntity = this.clientConsentRepository.findByAccountIdAndClientRegistrationId(accountId, clientRegistrationId)
                .orElseGet(() -> createAuthorizedClientEntity(accountId, clientRegistrationId))
                .withAdditionalScopes(authorizationConsent.getScopes());

        clientConsentEntity = this.clientConsentRepository.save(clientConsentEntity);

        try (AccountService.LoggingContext log = this.accountService.log(accountId, Map.of("type", "CONSENT", "client_id", clientRegistrationId))) {
            log.log(String.format("Updated consented oauth2-scopes to [%s]", String.join(", ", clientConsentEntity.authorizedScopes())));
        }
    }

    @Override
    public void remove(OAuth2AuthorizationConsent authorizationConsent) {
        final UUID accountId = UUID.fromString(authorizationConsent.getPrincipalName());
        final UUID registeredClientId = UUID.fromString(authorizationConsent.getRegisteredClientId());

        deleteClientConsent(accountId, registeredClientId);
    }

    @Override
    public OAuth2AuthorizationConsent findById(String registeredClientId, String principalName) {
        final UUID accountId = UUID.fromString(principalName);
        final UUID clientRegistrationId = UUID.fromString(registeredClientId);

        if (this.authorizationCodeParamAccessor.isInCodeRequest() && !this.authorizationCodeParamAccessor.isInConsentContext()) {
            if (this.authorizationCodeParamAccessor.getAdditionalParameters().filter((e) -> e.getKey().equals("prompt")).map(Map.Entry::getValue).anyMatch(Predicate.isEqual("consent"))) {
                return null;
            }

            final String copyGw2AccountIdsFromClientAuthorizationId = this.clientAuthorizationRepository.findLatestByAccountIdAndClientRegistrationIdAndHavingScopes(accountId, clientRegistrationId, this.authorizationCodeParamAccessor.getRequestedScopes())
                    .map(ClientAuthorizationEntity::id)
                    .orElse(null);

            if (copyGw2AccountIdsFromClientAuthorizationId == null) {
                return null;
            }

            this.authorizationCodeParamAccessor.putValue("COPY_FROM_CLIENT_AUTHORIZATION_ID", copyGw2AccountIdsFromClientAuthorizationId);
        }

        return this.clientConsentRepository.findByAccountIdAndClientRegistrationId(accountId, clientRegistrationId)
                .filter(ClientConsentServiceImpl::isAuthorized)
                .map((entity) -> {
                    final OAuth2AuthorizationConsent.Builder builder = OAuth2AuthorizationConsent.withId(entity.clientRegistrationId().toString(), entity.accountId().toString());
                    entity.authorizedScopes().forEach(builder::scope);

                    return builder.build();
                })
                .orElse(null);
    }
    // endregion

    private ClientConsentEntity createAuthorizedClientEntity(UUID accountId, UUID registeredClientId) {
        return new ClientConsentEntity(accountId, registeredClientId, UUID.randomUUID(), Set.of());
    }

    private static boolean isAuthorized(ClientConsentEntity clientConsentEntity) {
        return clientConsentEntity.authorizedScopes() != null && !clientConsentEntity.authorizedScopes().isEmpty();
    }
}
