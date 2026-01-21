package com.gw2auth.oauth2.server.service.application.client;

import com.gw2auth.oauth2.server.repository.application.ApplicationRepository;
import com.gw2auth.oauth2.server.repository.application.client.ApplicationClientEntity;
import com.gw2auth.oauth2.server.repository.application.client.ApplicationClientRepository;
import com.gw2auth.oauth2.server.service.Clocked;
import com.gw2auth.oauth2.server.service.OAuth2ClientApiVersion;
import com.gw2auth.oauth2.server.service.OAuth2Scope;
import com.gw2auth.oauth2.server.service.OAuth2ClientType;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.application.AuthorizationCodeParamAccessor;
import com.gw2auth.oauth2.server.service.application.AuthorizationCodeParamAccessorImpl;
import com.gw2auth.oauth2.server.util.UriPatternMatch;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
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

    private static final Logger LOG = LoggerFactory.getLogger(ApplicationClientServiceImpl.class);
    private static final int CLIENT_SECRET_LENGTH = 64;
    private static final String CLIENT_SECRET_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final Set<AuthorizationGrantType> ALLOWED_GRANT_TYPES = Set.of(
            AuthorizationGrantType.AUTHORIZATION_CODE,
            AuthorizationGrantType.REFRESH_TOKEN,
            AuthorizationGrantType.CLIENT_CREDENTIALS
    );

    private final AccountService accountService;
    private final ApplicationRepository applicationRepository;
    private final ApplicationClientRepository applicationClientRepository;
    private final RedirectUriValidator redirectUriValidator;
    private final PasswordEncoder passwordEncoder;
    private final AuthorizationCodeParamAccessor authorizationCodeParamAccessor;
    private Clock clock;

    @Autowired
    public ApplicationClientServiceImpl(AccountService accountService,
                                        ApplicationRepository applicationRepository,
                                        ApplicationClientRepository applicationClientRepository,
                                        RedirectUriValidator redirectUriValidator,
                                        PasswordEncoder passwordEncoder,
                                        AuthorizationCodeParamAccessor authorizationCodeParamAccessor) {

        this.accountService = accountService;
        this.applicationRepository = applicationRepository;
        this.applicationClientRepository = applicationClientRepository;
        this.redirectUriValidator = redirectUriValidator;
        this.passwordEncoder = passwordEncoder;
        this.authorizationCodeParamAccessor = authorizationCodeParamAccessor;
        this.clock = Clock.systemUTC();

        if (this.authorizationCodeParamAccessor instanceof AuthorizationCodeParamAccessorImpl accessor) {
            // hacky, happy for a workaround
            accessor.setRegisteredClientRepository(this);
        }
    }

    @Override
    public void setClock(Clock clock) {
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public Optional<ApplicationClient> getApplicationClient(UUID ids) {
        return this.applicationClientRepository.findById(ids).map(ApplicationClient::fromEntity);
    }

    @Override
    @Transactional
    public ApplicationClientCreation createApplicationClient(UUID accountId, UUID applicationId, String displayName, Set<String> authorizationGrantTypes, Set<String> redirectUris, OAuth2ClientApiVersion clientApiVersion, OAuth2ClientType clientType) {
        if (redirectUris.isEmpty()) {
            throw new ApplicationClientServiceException(ApplicationClientServiceException.NOT_ENOUGH_REDIRECT_URIS, HttpStatus.BAD_REQUEST);
        } else if (!redirectUris.stream().allMatch(this.redirectUriValidator::validate)) {
            throw new ApplicationClientServiceException(ApplicationClientServiceException.INVALID_REDIRECT_URI, HttpStatus.BAD_REQUEST);
        } else if (this.applicationRepository.findByIdAndAccountId(applicationId, accountId).isEmpty()) {
            throw new ApplicationClientServiceException(ApplicationClientServiceException.APPLICATION_NOT_FOUND, HttpStatus.NOT_FOUND);
        }

        final String clientSecret;
        final String encodedClientSecret;

        if (clientType == OAuth2ClientType.CONFIDENTIAL) {
            clientSecret = generateClientSecret();
            encodedClientSecret = this.passwordEncoder.encode(clientSecret);
        } else {
            clientSecret = null;
            encodedClientSecret = null;
        }

        final ApplicationClientEntity entity = this.applicationClientRepository.save(new ApplicationClientEntity(
                UUID.randomUUID(),
                applicationId,
                this.clock.instant(),
                displayName,
                encodedClientSecret,
                authorizationGrantTypes,
                redirectUris,
                false,
                clientApiVersion.value(),
                clientType.name()
        ));

        this.accountService.log(
                accountId,
                String.format("New client '%s' created", entity.displayName()),
                Map.of("application_id", applicationId, "client_id", entity.id())
        );

        return new ApplicationClientCreation(ApplicationClient.fromEntity(entity), clientSecret);
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
        final UUID registeredClientId = UUID.fromString(registeredClient.getClientId());

        LOG.warn("received call to save(RegisteredClient) for client {}", registeredClientId);

        final ApplicationClientEntity entity = this.applicationClientRepository.findById(registeredClientId).orElseThrow();
        this.applicationClientRepository.save(
                entity.id(),
                entity.applicationId(),
                entity.creationTime(),
                entity.displayName(),
                registeredClient.getClientSecret(), // is currently only used to update secret, so only update that one
                entity.authorizationGrantTypes(),
                entity.redirectUris(),
                entity.requiresApproval(),
                entity.apiVersion(),
                entity.type()
        );
    }

    @Override
    public @Nullable RegisteredClient findById(String id) {
        final UUID registeredClientId = UUID.fromString(id);
        return this.applicationClientRepository.findById(registeredClientId).map(this::registeredClientFromEntity).orElse(null);
    }

    @Override
    public @Nullable RegisteredClient findByClientId(String clientId) {
        return findById(clientId);
    }

    private RegisteredClient registeredClientFromEntity(ApplicationClientEntity entity) {
        final Set<String> redirectUris;
        final String requestedRedirectUri = this.authorizationCodeParamAccessor.getCodeRequest()
                .map(OAuth2AuthorizationCodeRequestAuthenticationToken::getRedirectUri)
                .orElse(null);

        if (requestedRedirectUri != null && !entity.redirectUris().contains(requestedRedirectUri)) {
            redirectUris = entity.redirectUris().stream()
                    .map((redirectUri) -> {
                        if (UriPatternMatch.matches(redirectUri, requestedRedirectUri)) {
                            return requestedRedirectUri;
                        }

                        return redirectUri;
                    })
                    .collect(Collectors.toUnmodifiableSet());
        } else {
            redirectUris = entity.redirectUris();
        }

        final RegisteredClient.Builder builder = RegisteredClient.withId(entity.id().toString())
                .clientName(entity.displayName())
                .clientId(entity.id().toString())
                .clientIdIssuedAt(entity.creationTime())
                .redirectUris((v) -> v.addAll(redirectUris))
                .clientSettings(
                        ClientSettings.builder()
                                .requireAuthorizationConsent(true)
                                .requireProofKey(OAuth2ClientType.valueOf(entity.type()) == OAuth2ClientType.PUBLIC)
                                .build()
                )
                .tokenSettings(
                        TokenSettings.builder()
                                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                                .accessTokenTimeToLive(Duration.ofMinutes(30L))
                                .refreshTokenTimeToLive(Duration.ofDays(180L))
                                .reuseRefreshTokens(false)
                                .build()
                );

        entity.authorizationGrantTypes().stream()
                .map(AuthorizationGrantType::new)
                .filter(ALLOWED_GRANT_TYPES::contains)
                .forEach(builder::authorizationGrantType);

        switch (OAuth2ClientType.valueOf(entity.type())) {
            case CONFIDENTIAL -> builder
                    .clientSecret(Objects.requireNonNull(entity.clientSecret()))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST);
            case PUBLIC -> builder
                    .clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
        }

        final OAuth2ClientApiVersion clientApiVersion = OAuth2ClientApiVersion.fromValueRequired(entity.apiVersion());
        OAuth2Scope.allForVersion(clientApiVersion)
                .map(OAuth2Scope::oauth2)
                .forEach(builder::scope);

        return new SpringRegisteredClient(builder.build(), ApplicationClient.fromEntity(entity));
    }
    // endregion
}
