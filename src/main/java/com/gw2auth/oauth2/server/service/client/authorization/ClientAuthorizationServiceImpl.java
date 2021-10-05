package com.gw2auth.oauth2.server.service.client.authorization;

import com.gw2auth.oauth2.server.adapt.CustomOAuth2AuthorizationCodeRequestAuthenticationProvider;
import com.gw2auth.oauth2.server.repository.client.authorization.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

@Service
public class ClientAuthorizationServiceImpl implements ClientAuthorizationService, OAuth2AuthorizationConsentService {

    private static final int MAX_LOG_COUNT = 50;

    private final ClientAuthorizationRepository clientAuthorizationRepository;
    private final ClientAuthorizationTokenRepository clientAuthorizationTokenRepository;
    private final ClientAuthorizationLogRepository clientAuthorizationLogRepository;

    @Autowired
    public ClientAuthorizationServiceImpl(ClientAuthorizationRepository clientAuthorizationRepository, ClientAuthorizationTokenRepository clientAuthorizationTokenRepository, ClientAuthorizationLogRepository clientAuthorizationLogRepository) {
        this.clientAuthorizationRepository = clientAuthorizationRepository;
        this.clientAuthorizationTokenRepository = clientAuthorizationTokenRepository;
        this.clientAuthorizationLogRepository = clientAuthorizationLogRepository;
    }

    @Override
    public List<ClientAuthorization> getClientAuthorizations(long accountId) {
        return getClientAuthorizationsInternal(accountId, this.clientAuthorizationRepository.findAllByAccountId(accountId));
    }

    @Override
    public List<ClientAuthorization> getClientAuthorizations(long accountId, Set<String> gw2AccountIds) {
        return getClientAuthorizationsInternal(accountId, this.clientAuthorizationRepository.findAllByAccountIdAndLinkedTokens(accountId, gw2AccountIds));
    }

    private List<ClientAuthorization> getClientAuthorizationsInternal(long accountId, List<ClientAuthorizationEntity> clientAuthorizationEntities) {
        clientAuthorizationEntities = clientAuthorizationEntities.stream()
                .filter(ClientAuthorizationServiceImpl::isAuthorized)
                .collect(Collectors.toList());

        final Set<Long> clientRegistrationIds = clientAuthorizationEntities.stream()
                .map(ClientAuthorizationEntity::clientRegistrationId)
                .collect(Collectors.toSet());

        final Map<Long, List<ClientAuthorizationTokenEntity>> clientAuthorizationTokensByRegistrationId = this.clientAuthorizationTokenRepository.findAllByAccountIdAndClientRegistrationIds(accountId, clientRegistrationIds).stream()
                .collect(Collectors.groupingBy(ClientAuthorizationTokenEntity::clientRegistrationId));

        final List<ClientAuthorization> clientAuthorizations = new ArrayList<>(clientAuthorizationEntities.size());

        for (ClientAuthorizationEntity clientAuthorizationEntity : clientAuthorizationEntities) {
            final List<ClientAuthorizationTokenEntity> clientAuthorizationTokenEntities = clientAuthorizationTokensByRegistrationId.getOrDefault(clientAuthorizationEntity.clientRegistrationId(), List.of());
            clientAuthorizations.add(ClientAuthorization.fromEntity(clientAuthorizationEntity, clientAuthorizationTokenEntities));
        }

        return clientAuthorizations;
    }

    @Override
    public Optional<ClientAuthorization> getClientAuthorization(long accountId, long clientRegistrationId) {
        return this.clientAuthorizationRepository.findByAccountIdAndClientRegistrationId(accountId, clientRegistrationId)
                .filter(ClientAuthorizationServiceImpl::isAuthorized)
                .map((clientAuthorizationEntity) -> ClientAuthorization.fromEntity(clientAuthorizationEntity, this.clientAuthorizationTokenRepository.findAllByAccountIdAndClientRegistrationId(accountId, clientRegistrationId)));
    }

    @Override
    @Transactional
    public void createEmptyClientAuthorizationIfNotExists(long accountId, long clientRegistrationId) {
        final Optional<ClientAuthorizationEntity> optional = this.clientAuthorizationRepository.findByAccountIdAndClientRegistrationId(accountId, clientRegistrationId);
        if (optional.isEmpty()) {
            this.clientAuthorizationRepository.save(createAuthorizedClientEntity(accountId, clientRegistrationId));
        }
    }

    @Override
    @Transactional
    public void deleteClientAuthorization(long accountId, String clientId) {
        this.clientAuthorizationRepository.findByAccountIdAndClientId(accountId, clientId).ifPresent(this::deleteInternal);
    }

    @Override
    @Transactional
    public void deleteClientAuthorization(long accountId, long clientRegistrationId) {
        this.clientAuthorizationRepository.findByAccountIdAndClientRegistrationId(accountId, clientRegistrationId).ifPresent(this::deleteInternal);
    }

    @Transactional
    protected void deleteInternal(ClientAuthorizationEntity entity) {
        // not actually deleting, since we want to keep the client specific account sub

        entity = entity.withAuthorizedScopes(Set.of());

        entity = this.clientAuthorizationRepository.save(entity);
        this.clientAuthorizationTokenRepository.deleteAllByAccountIdAndClientRegistrationId(entity.accountId(), entity.clientRegistrationId());
        this.clientAuthorizationLogRepository.deleteAllByAccountIdAndClientRegistrationId(entity.accountId(), entity.clientRegistrationId());
    }

    @Override
    @Transactional
    public void updateTokens(long accountId, long clientRegistrationId, Map<String, ClientAuthorization.Token> tokens) {
        this.clientAuthorizationTokenRepository.saveAll(
                tokens.entrySet().stream()
                        .map((e) -> new ClientAuthorizationTokenEntity(accountId, clientRegistrationId, e.getKey(), e.getValue().gw2ApiSubtoken(), e.getValue().expirationTime()))
                        .collect(Collectors.toList())
        );
    }

    @Override
    public LoggingContext log(long accountId, long clientRegistrationId) {
        return new LoggingContextImpl(accountId, clientRegistrationId);
    }

    // region OAuth2AuthorizationConsentService
    @Override
    @Transactional
    public void save(OAuth2AuthorizationConsent authorizationConsent) {
        final long accountId = Long.parseLong(authorizationConsent.getPrincipalName());
        final long clientRegistrationId = Long.parseLong(authorizationConsent.getRegisteredClientId());

        ClientAuthorizationEntity clientAuthorizationEntity = this.clientAuthorizationRepository.findByAccountIdAndClientRegistrationId(accountId, clientRegistrationId)
                .orElseGet(() -> createAuthorizedClientEntity(accountId, clientRegistrationId))
                .withAuthorizedScopes(authorizationConsent.getScopes());

        clientAuthorizationEntity = this.clientAuthorizationRepository.save(clientAuthorizationEntity);

        final Set<String> authorizedTokenGw2AccountIds = CustomOAuth2AuthorizationCodeRequestAuthenticationProvider.getAdditionalParameters()
                .map(Map.Entry::getKey)
                .filter((v) -> v.startsWith("token:"))
                .map((v) -> v.replaceFirst("token:", ""))
                .collect(Collectors.toSet());

        if (authorizedTokenGw2AccountIds.isEmpty()) {
            //throw new OAuth2AuthorizationCodeRequestAuthenticationException();
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED));
        }

        final Map<String, ClientAuthorization.Token> tokens = new HashMap<>(authorizedTokenGw2AccountIds.size());
        for (String authorizedTokenGw2AccountId : authorizedTokenGw2AccountIds) {
            tokens.put(authorizedTokenGw2AccountId, new ClientAuthorization.Token("", Instant.now()));
        }

        this.clientAuthorizationTokenRepository.deleteAllByAccountIdAndClientRegistrationId(accountId, clientRegistrationId);
        updateTokens(accountId, clientRegistrationId, tokens);
    }

    @Override
    public void remove(OAuth2AuthorizationConsent authorizationConsent) {
        final long accountId = Long.parseLong(authorizationConsent.getPrincipalName());
        final long registeredClientId = Long.parseLong(authorizationConsent.getRegisteredClientId());

        deleteClientAuthorization(accountId, registeredClientId);
    }

    @Override
    public OAuth2AuthorizationConsent findById(String _registeredClientId, String principalName) {
        final long accountId = Long.parseLong(principalName);
        final long registeredClientId = Long.parseLong(_registeredClientId);

        return this.clientAuthorizationRepository.findByAccountIdAndClientRegistrationId(accountId, registeredClientId)
                .filter(ClientAuthorizationServiceImpl::isAuthorized)
                .map((clientAuthorizationEntity) -> {
                    final OAuth2AuthorizationConsent.Builder builder = OAuth2AuthorizationConsent.withId(Long.toString(clientAuthorizationEntity.clientRegistrationId()), Long.toString(clientAuthorizationEntity.accountId()));
                    clientAuthorizationEntity.authorizedScopes().forEach(builder::scope);

                    return builder.build();
                })
                .orElse(null);
    }
    // endregion

    private ClientAuthorizationEntity createAuthorizedClientEntity(long accountId, long registeredClientId) {
        return new ClientAuthorizationEntity(accountId, registeredClientId, UUID.randomUUID(), Set.of());
    }

    private static boolean isAuthorized(ClientAuthorizationEntity clientAuthorizationEntity) {
        return clientAuthorizationEntity.authorizedScopes() != null && !clientAuthorizationEntity.authorizedScopes().isEmpty();
    }

    private final class LoggingContextImpl implements LoggingContext {

        private final long accountId;
        private final long clientRegistrationId;
        private final Instant timestamp;
        private final List<String> messages;
        private final AtomicBoolean isValid;

        private LoggingContextImpl(long accountId, long clientRegistrationId) {
            this.accountId = accountId;
            this.clientRegistrationId = clientRegistrationId;
            this.timestamp = Instant.now();
            this.messages = new LinkedList<>();
            this.isValid = new AtomicBoolean(true);
        }

        @Override
        public void log(String message) {
            // not truly thread-safe
            // this is a optimistic variant. I'm in control of all users of these methods
            if (this.isValid.get()) {
                this.messages.add(message);
            }
        }

        @Override
        public void close() {
            if (this.isValid.compareAndSet(true, false)) {
                ClientAuthorizationServiceImpl.this.clientAuthorizationLogRepository.deleteAllByAccountIdAndClientRegistrationIdExceptLatestN(this.accountId, this.clientRegistrationId, MAX_LOG_COUNT - 1);
                ClientAuthorizationServiceImpl.this.clientAuthorizationLogRepository.save(new ClientAuthorizationLogEntity(null, this.accountId, this.clientRegistrationId, this.timestamp, this.messages));
                this.messages.clear();
            }
        }
    }
}
