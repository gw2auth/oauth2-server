package com.gw2auth.oauth2.server.service.application.client;

import com.gw2auth.oauth2.server.repository.application.ApplicationRepository;
import com.gw2auth.oauth2.server.repository.application.client.ApplicationClientEntity;
import com.gw2auth.oauth2.server.repository.application.client.ApplicationClientRepository;
import com.gw2auth.oauth2.server.service.Clocked;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.application.client.account.ApplicationClientAccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class ApplicationClientServiceImpl implements ApplicationClientService, RegisteredClientRepository, Clocked {

    private static final int CLIENT_SECRET_LENGTH = 64;
    private static final String CLIENT_SECRET_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final Set<AuthorizationGrantType> ALLOWED_GRANT_TYPES = Set.of(AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.REFRESH_TOKEN, AuthorizationGrantType.CLIENT_CREDENTIALS);

    private final AccountService accountService;
    private final ApplicationRepository applicationRepository;
    private final ApplicationClientRepository applicationClientRepository;
    private final RedirectUriValidator redirectUriValidator;
    private final PasswordEncoder passwordEncoder;
    private Clock clock;

    @Autowired
    public ApplicationClientServiceImpl(AccountService accountService,
                                        ApplicationRepository applicationRepository,
                                        ApplicationClientRepository applicationClientRepository,
                                        RedirectUriValidator redirectUriValidator,
                                        PasswordEncoder passwordEncoder) {

        this.accountService = accountService;
        this.applicationRepository = applicationRepository;
        this.applicationClientRepository = applicationClientRepository;
        this.redirectUriValidator = redirectUriValidator;
        this.passwordEncoder = passwordEncoder;
        this.clock = Clock.systemUTC();
    }

    @Override
    public void setClock(Clock clock) {
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public List<ApplicationClient> getApplicationClients(UUID accountId) {
        return this.applicationClientRepository.findAllByAccountId(accountId).stream()
                .map(ApplicationClient::fromEntity)
                .toList();
    }

    @Override
    public Optional<ApplicationClient> getApplicationClient(UUID accountId, UUID id) {
        return this.applicationClientRepository.findByIdAndAccountId(id, accountId)
                .map(ApplicationClient::fromEntity);
    }

    @Override
    public List<ApplicationClient> getApplicationClients(Collection<UUID> ids) {
        return this.applicationClientRepository.findAllByIds(ids).stream()
                .map(ApplicationClient::fromEntity)
                .toList();
    }

    @Override
    @Transactional
    public ApplicationClientCreation createApplicationClient(UUID accountId, UUID applicationId, String displayName, Set<String> _authorizationGrantTypes, Set<String> redirectUris) {
        if (redirectUris.isEmpty()) {
            throw new ApplicationClientServiceException(ApplicationClientServiceException.NOT_ENOUGH_REDIRECT_URIS, HttpStatus.BAD_REQUEST);
        } else if (!redirectUris.stream().allMatch(this.redirectUriValidator::validate)) {
            throw new ApplicationClientServiceException(ApplicationClientServiceException.INVALID_REDIRECT_URI, HttpStatus.BAD_REQUEST);
        } else if (this.applicationRepository.findByIdAndAccountId(applicationId, accountId).isEmpty()) {
            throw new ApplicationClientServiceException(ApplicationClientServiceException.APPLICATION_NOT_FOUND, HttpStatus.NOT_FOUND);
        }

        final Set<AuthorizationGrantType> authorizationGrantTypes = _authorizationGrantTypes.stream()
                .map(AuthorizationGrantType::new)
                //.filter(ALLOWED_GRANT_TYPES::contains) -> dont filter here. We filter before giving it to spring (if we support the requested scopes in the future, they can be used directly)
                .collect(Collectors.toSet());

        final String clientSecret = generateClientSecret();
        final String encodedClientSecret = this.passwordEncoder.encode(clientSecret);

        final ApplicationClientEntity entity = this.applicationClientRepository.save(new ApplicationClientEntity(
                UUID.randomUUID(),
                applicationId,
                this.clock.instant(),
                displayName,
                encodedClientSecret,
                authorizationGrantTypes.stream().map(AuthorizationGrantType::getValue).collect(Collectors.toSet()),
                redirectUris,
                false
        ));

        this.accountService.log(
                accountId,
                String.format("New client '%s' created", entity.displayName()),
                Map.of("application_id", applicationId, "client_id", entity.id())
        );

        return ApplicationClientCreation.fromEntity(entity, clientSecret);
    }

    @Override
    @Transactional
    public ApplicationClient addRedirectUri(UUID accountId, UUID id, String redirectUri) {
        if (!this.redirectUriValidator.validate(redirectUri)) {
            throw new ApplicationClientServiceException(ApplicationClientServiceException.INVALID_REDIRECT_URI, HttpStatus.BAD_REQUEST);
        }

        ApplicationClientEntity entity = this.applicationClientRepository.findByIdAndAccountId(id, accountId)
                .orElseThrow(() -> new ApplicationClientServiceException(ApplicationClientServiceException.NOT_FOUND, HttpStatus.NOT_FOUND));

        entity.redirectUris().add(redirectUri);
        entity = this.applicationClientRepository.save(entity);

        this.accountService.log(
                accountId,
                String.format("Redirect-URI '%s' added", redirectUri),
                Map.of("application_id", entity.applicationId(), "client_id", entity.id())
        );

        return ApplicationClient.fromEntity(entity);
    }

    @Override
    @Transactional
    public ApplicationClient removeRedirectUri(UUID accountId, UUID id, String redirectUri) {
        ApplicationClientEntity entity = this.applicationClientRepository.findByIdAndAccountId(id, accountId)
                .orElseThrow(() -> new ApplicationClientServiceException(ApplicationClientServiceException.NOT_FOUND, HttpStatus.NOT_FOUND));

        entity.redirectUris().remove(redirectUri);

        if (entity.redirectUris().isEmpty()) {
            throw new ApplicationClientServiceException(ApplicationClientServiceException.NOT_ENOUGH_REDIRECT_URIS, HttpStatus.BAD_REQUEST);
        }

        entity = this.applicationClientRepository.save(entity);

        this.accountService.log(
                accountId,
                String.format("Redirect-URI '%s' removed", redirectUri),
                Map.of("application_id", entity.applicationId(), "client_id", entity.id())
        );

        return ApplicationClient.fromEntity(entity);
    }

    @Override
    @Transactional
    public ApplicationClientCreation regenerateClientSecret(UUID accountId, UUID id) {
        ApplicationClientEntity entity = this.applicationClientRepository.findByIdAndAccountId(id, accountId)
                .orElseThrow(() -> new ApplicationClientServiceException(ApplicationClientServiceException.NOT_FOUND, HttpStatus.NOT_FOUND));

        final String clientSecret = generateClientSecret();
        final String encodedClientSecret = this.passwordEncoder.encode(clientSecret);

        entity = this.applicationClientRepository.save(new ApplicationClientEntity(
                entity.id(),
                entity.applicationId(),
                entity.creationTime(),
                entity.displayName(),
                encodedClientSecret,
                entity.authorizationGrantTypes(),
                entity.redirectUris(),
                entity.requiresApproval()
        ));

        this.accountService.log(
                accountId,
                "Client-Secret regenerated",
                Map.of("application_id", entity.applicationId(), "client_id", entity.id())
        );

        return ApplicationClientCreation.fromEntity(entity, clientSecret);
    }

    @Override
    @Transactional
    public void deleteClientRegistration(UUID accountId, UUID id) {
        if (!this.applicationClientRepository.deleteByIdAndAccountId(id, accountId)) {
            throw new ApplicationClientServiceException(ApplicationClientServiceException.NOT_FOUND, HttpStatus.NOT_FOUND);
        }

        this.accountService.log(
                accountId,
                "The client has been deleted",
                Map.of("application_id", "*", "client_id", id)
        );
    }

    private String generateClientSecret() {
        final Random random = new SecureRandom();
        final StringBuilder sb = new StringBuilder(CLIENT_SECRET_LENGTH);

        for (int i = 0; i < CLIENT_SECRET_LENGTH; i++) {
            sb.append(CLIENT_SECRET_CHARS.charAt(random.nextInt(CLIENT_SECRET_CHARS.length())));
        }

        return sb.toString();
    }

    // region Spring OAuth2
    @Override
    public void save(RegisteredClient registeredClient) {
        // should only be done through the other methods
        throw new UnsupportedOperationException();
    }

    @Override
    public RegisteredClient findById(String id) {
        final UUID registeredClientId = UUID.fromString(id);
        return this.applicationClientRepository.findById(registeredClientId).map(ApplicationClientServiceImpl::registeredClientFromEntity).orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return findById(clientId);
    }

    private static RegisteredClient registeredClientFromEntity(ApplicationClientEntity entity) {
        final RegisteredClient.Builder builder = RegisteredClient.withId(entity.id().toString())
                .clientName(entity.displayName())
                .clientId(entity.id().toString())
                .clientSecret(entity.clientSecret())
                .clientIdIssuedAt(entity.creationTime())
                .redirectUris((v) -> v.addAll(entity.redirectUris()))
                //.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                //.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .tokenSettings(
                        TokenSettings.builder()
                                .accessTokenTimeToLive(Duration.ofMinutes(30L))
                                .refreshTokenTimeToLive(Duration.ofDays(180L))
                                .reuseRefreshTokens(false)
                                .build()
                );

        entity.authorizationGrantTypes().stream()
                .map(AuthorizationGrantType::new)
                .filter(ALLOWED_GRANT_TYPES::contains)
                .forEach(builder::authorizationGrantType);

        Gw2ApiPermission.stream()
                .map(Gw2ApiPermission::oauth2)
                .forEach(builder::scope);

        builder.scope(ApplicationClientAccountService.GW2AUTH_VERIFIED_SCOPE);

        return new SpringRegisteredClient(builder.build(), ApplicationClient.fromEntity(entity));
    }
    // endregion
}
