package com.gw2auth.oauth2.server.service.client.registration;

import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.repository.client.registration.ClientRegistrationRepository;
import com.gw2auth.oauth2.server.repository.client.registration.ClientRegistrationEntity;
import com.gw2auth.oauth2.server.service.client.consent.ClientConsentService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

@Service
public class ClientRegistrationServiceImpl implements ClientRegistrationService, RegisteredClientRepository {

    private static final int CLIENT_SECRET_LENGTH = 64;
    private static final String CLIENT_SECRET_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final Set<AuthorizationGrantType> ALLOWED_GRANT_TYPES = Set.of(AuthorizationGrantType.AUTHORIZATION_CODE, AuthorizationGrantType.REFRESH_TOKEN, AuthorizationGrantType.CLIENT_CREDENTIALS);

    private final ClientRegistrationRepository clientRegistrationRepository;
    private final RedirectUriValidator redirectUriValidator;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ClientRegistrationServiceImpl(ClientRegistrationRepository clientRegistrationRepository, RedirectUriValidator redirectUriValidator, PasswordEncoder passwordEncoder) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.redirectUriValidator = redirectUriValidator;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public List<ClientRegistration> getClientRegistrations(long accountId) {
        return this.clientRegistrationRepository.findAllByAccountId(accountId).stream().map(ClientRegistration::fromEntity).collect(Collectors.toList());
    }

    @Override
    public Optional<ClientRegistration> getClientRegistration(long accountId, String clientId) {
        return this.clientRegistrationRepository.findByAccountIdIdAndClientId(accountId, clientId).map(ClientRegistration::fromEntity);
    }

    @Override
    public List<ClientRegistration> getClientRegistrations(Collection<Long> ids) {
        return StreamSupport.stream(this.clientRegistrationRepository.findAllById(ids).spliterator(), false)
                .map(ClientRegistration::fromEntity)
                .collect(Collectors.toList());
    }

    @Override
    public Optional<ClientRegistration> getClientRegistration(String clientId) {
        return this.clientRegistrationRepository.findByClientId(clientId).map(ClientRegistration::fromEntity);
    }

    @Override
    @Transactional
    public ClientRegistrationCreation createClientRegistration(long accountId, String displayName, Set<String> _authorizationGrantTypes, String redirectUri) {
        if (!this.redirectUriValidator.validate(redirectUri)) {
            throw new ClientRegistrationServiceException(ClientRegistrationServiceException.INVALID_REDIRECT_URI, HttpStatus.BAD_REQUEST);
        }

        final Set<AuthorizationGrantType> authorizationGrantTypes = _authorizationGrantTypes.stream()
                .map(AuthorizationGrantType::new)
                //.filter(ALLOWED_GRANT_TYPES::contains) -> dont filter here. We filter before giving it to spring (if we support the requested scopes in the future, they can be used directly)
                .collect(Collectors.toSet());

        final String clientSecret = generateClientSecret();
        final String encodedClientSecret = this.passwordEncoder.encode(clientSecret);

        final ClientRegistrationEntity clientRegistrationEntity = this.clientRegistrationRepository.save(new ClientRegistrationEntity(
                null,
                accountId,
                Instant.now(),
                displayName,
                generateClientId(),
                encodedClientSecret,
                authorizationGrantTypes.stream().map(AuthorizationGrantType::getValue).collect(Collectors.toSet()),
                redirectUri
        ));

        return ClientRegistrationCreation.fromEntity(clientRegistrationEntity, clientSecret);
    }

    @Override
    public void deleteClientRegistration(long accountId, String clientId) {
        if (!this.clientRegistrationRepository.deleteByAccountIdIdAndClientId(accountId, clientId)) {
            // return not found since we dont want the user to know this client id exists
            throw new ClientRegistrationServiceException(ClientRegistrationServiceException.NOT_FOUND, HttpStatus.NOT_FOUND);
        }
    }

    private String generateClientId() {
        return UUID.randomUUID().toString();
    }

    private String generateClientSecret() {
        final Random random = new SecureRandom();
        final StringBuilder sb = new StringBuilder(CLIENT_SECRET_LENGTH);

        for (int i = 0; i < CLIENT_SECRET_LENGTH; i++) {
            sb.append(CLIENT_SECRET_CHARS.charAt(random.nextInt(CLIENT_SECRET_CHARS.length())));
        }

        return sb.toString();
    }

    private static RegisteredClient registeredClientFromEntity(ClientRegistrationEntity entity) {
        final RegisteredClient.Builder builder = RegisteredClient.withId(Long.toString(entity.id()))
                .clientName(entity.displayName())
                .clientId(entity.clientId())
                .clientSecret(entity.clientSecret())
                .clientIdIssuedAt(entity.creationTime())
                .redirectUri(entity.redirectUri())
                .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)// TODO: check if this is still a thing in 0.2.0
                .clientAuthenticationMethod(ClientAuthenticationMethod.POST)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
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

        builder.scope(ClientConsentService.GW2AUTH_VERIFIED_SCOPE);

        return builder.build();
    }

    // region spring RegisteredClientRepository
    @Override
    public void save(RegisteredClient registeredClient) {
        // should only be done through the other methods
        throw new UnsupportedOperationException();
    }

    @Override
    public RegisteredClient findById(String id) {
        final long registeredClientId = Long.parseLong(id);
        return this.clientRegistrationRepository.findById(registeredClientId).map(ClientRegistrationServiceImpl::registeredClientFromEntity).orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return this.clientRegistrationRepository.findByClientId(clientId).map(ClientRegistrationServiceImpl::registeredClientFromEntity).orElse(null);
    }
    // endregion
}
