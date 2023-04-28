package com.gw2auth.oauth2.server.service.application.client.authorization;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gw2auth.oauth2.server.adapt.Java9CollectionJackson2Module;
import com.gw2auth.oauth2.server.adapt.LinkedHashSetJackson2Module;
import com.gw2auth.oauth2.server.repository.application.client.authorization.ApplicationClientAuthorizationEntity;
import com.gw2auth.oauth2.server.repository.application.client.authorization.ApplicationClientAuthorizationRepository;
import com.gw2auth.oauth2.server.repository.application.client.authorization.ApplicationClientAuthorizationTokenEntity;
import com.gw2auth.oauth2.server.repository.application.client.authorization.ApplicationClientAuthorizationTokenRepository;
import com.gw2auth.oauth2.server.service.Clocked;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.application.AuthorizationCodeParamAccessor;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUser;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUserMixin;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUserV2;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUserV2Mixin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.security.Principal;
import java.time.Clock;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
@EnableScheduling
public class ApplicationClientAuthorizationServiceImpl implements ApplicationClientAuthorizationService, OAuth2AuthorizationService, Clocked {

    private static final Logger LOG = LoggerFactory.getLogger(ApplicationClientAuthorizationServiceImpl.class);

    private final AccountService accountService;
    private final ApplicationClientAuthorizationRepository applicationClientAuthorizationRepository;
    private final ApplicationClientAuthorizationTokenRepository applicationClientAuthorizationTokenRepository;
    private final RegisteredClientRepository registeredClientRepository;
    private final AuthorizationCodeParamAccessor authorizationCodeParamAccessor;
    private final ObjectMapper objectMapper;
    private final boolean isTest;
    private Clock clock;

    @Autowired
    public ApplicationClientAuthorizationServiceImpl(Environment environment,
                                                     AccountService accountService,
                                                     ApplicationClientAuthorizationRepository applicationClientAuthorizationRepository,
                                                     ApplicationClientAuthorizationTokenRepository applicationClientAuthorizationTokenRepository,
                                                     RegisteredClientRepository registeredClientRepository,
                                                     AuthorizationCodeParamAccessor authorizationCodeParamAccessor) {
        this.accountService = accountService;

        this.applicationClientAuthorizationRepository = applicationClientAuthorizationRepository;
        this.applicationClientAuthorizationTokenRepository = applicationClientAuthorizationTokenRepository;
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationCodeParamAccessor = authorizationCodeParamAccessor;
        this.objectMapper = new ObjectMapper();
        this.isTest = environment.acceptsProfiles(Profiles.of("test"));
        this.clock = Clock.systemUTC();

        final ClassLoader classLoader = ApplicationClientAuthorizationServiceImpl.class.getClassLoader();
        final List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        this.objectMapper.registerModules(securityModules);
        this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
        this.objectMapper.registerModule(new Java9CollectionJackson2Module());
        this.objectMapper.registerModule(new LinkedHashSetJackson2Module());
        this.objectMapper.addMixIn(Gw2AuthUser.class, Gw2AuthUserMixin.class);
        this.objectMapper.addMixIn(Gw2AuthUserV2.class, Gw2AuthUserV2Mixin.class);
    }

    @Override
    public void setClock(Clock clock) {
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public List<ApplicationClientAuthorization> getApplicationClientAuthorizations(UUID accountId, UUID applicationClientId) {
        return this.applicationClientAuthorizationRepository.findAllWithGw2AccountIdsByAccountIdAndApplicationClientId(accountId, applicationClientId).stream()
                .map(ApplicationClientAuthorization::fromEntity)
                .toList();
    }

    @Override
    public List<ApplicationClientAuthorization> getApplicationClientAuthorizations(UUID accountId, Collection<UUID> gw2AccountIds) {
        return this.applicationClientAuthorizationRepository.findAllWithGw2AccountIdsByAccountIdAndLinkedGw2AccountIds(accountId, gw2AccountIds).stream()
                .map(ApplicationClientAuthorization::fromEntity)
                .toList();
    }

    @Override
    public Optional<ApplicationClientAuthorization> getApplicationClientAuthorization(UUID accountId, String id) {
        return this.applicationClientAuthorizationRepository.findWithGw2AccountIdsByIdAndAccountId(id, accountId)
                .map(ApplicationClientAuthorization::fromEntity);
    }

    @Override
    public void deleteApplicationClientAuthorization(UUID accountId, String id) {
        if (!this.applicationClientAuthorizationRepository.deleteByIdAndAccountId(id, accountId)) {
            throw new ApplicationClientAuthorizationServiceException(ApplicationClientAuthorizationServiceException.NOT_FOUND, HttpStatus.NOT_FOUND);
        }
    }

    // region Spring OAuth2
    @Override
    @Transactional
    public void save(OAuth2Authorization authorization) {
        // validate only known keys are persisted
        final Set<String> authorizationAttributesKeys = new HashSet<>(authorization.getAttributes().keySet());
        authorizationAttributesKeys.remove(OAuth2AuthorizationRequest.class.getName());
        authorizationAttributesKeys.remove(Principal.class.getName());
        authorizationAttributesKeys.remove(OAuth2ParameterNames.STATE);

        if (!authorizationAttributesKeys.isEmpty()) {
            LOG.error("authorization.attributes contains more keys than expected; unexpected keys: {}", authorizationAttributesKeys);

            if (this.isTest) {
                // test should fail hard if we encounter unknown keys
                throw new IllegalArgumentException("authorization.attributes contains more keys than expected; unexpected keys: " + authorizationAttributesKeys);
            }
        }

        // actual logic
        final UUID accountId = UUID.fromString(authorization.getPrincipalName());
        final UUID applicationClientId = UUID.fromString(authorization.getRegisteredClientId());

        final Optional<OAuth2Authorization.Token<OAuth2AuthorizationCode>> authorizationCode = Optional.ofNullable(authorization.getToken(OAuth2AuthorizationCode.class));
        final Optional<OAuth2Authorization.Token<OAuth2AccessToken>> accessToken = Optional.ofNullable(authorization.getAccessToken());
        final Optional<OAuth2Authorization.Token<OAuth2RefreshToken>> refreshToken = Optional.ofNullable(authorization.getRefreshToken());

        final Map<String, Object> attributes = new HashMap<>(authorization.getAttributes());
        final Set<String> authorizedScopes = authorization.getAuthorizedScopes();

        final String name;

        if (this.authorizationCodeParamAccessor.isInCodeRequest()) {
            name = this.authorizationCodeParamAccessor.getAdditionalParameters()
                    .filter((e) -> e.getKey().equals(AUTHORIZATION_NAME_PARAM))
                    .map(Map.Entry::getValue)
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .findFirst()
                    .orElse(null);
        } else {
            name = null;
        }

        final Instant now = this.clock.instant();
        final ApplicationClientAuthorizationEntity entity = this.applicationClientAuthorizationRepository.save(new ApplicationClientAuthorizationEntity(
                authorization.getId(),
                accountId,
                applicationClientId,
                now,
                now,
                Optional.ofNullable(name).orElse(authorization.getId()),
                authorization.getAuthorizationGrantType().getValue(),
                Optional.ofNullable(authorizedScopes).orElse(Set.of()),
                writeJson(attributes),
                authorization.getAttribute(OAuth2ParameterNames.STATE),
                authorizationCode.map(OAuth2Authorization.Token::getToken).map(AbstractOAuth2Token::getTokenValue).orElse(null),
                authorizationCode.map(OAuth2Authorization.Token::getToken).map(AbstractOAuth2Token::getIssuedAt).orElse(null),
                authorizationCode.map(this::getTokenExpiresAt).orElse(null),
                authorizationCode.map(OAuth2Authorization.Token::getMetadata).map(this::writeJson).orElse(null),
                accessToken.map(OAuth2Authorization.Token::getToken).map(AbstractOAuth2Token::getTokenValue).orElse(null),
                accessToken.map(OAuth2Authorization.Token::getToken).map(AbstractOAuth2Token::getIssuedAt).orElse(null),
                accessToken.map(this::getTokenExpiresAt).orElse(null),
                accessToken.map(OAuth2Authorization.Token::getMetadata).map(this::writeJson).orElse(null),
                accessToken.map(OAuth2Authorization.Token::getToken).map((v) -> v.getTokenType().getValue()).orElse(null),
                accessToken.map(OAuth2Authorization.Token::getToken).map(OAuth2AccessToken::getScopes).orElse(Set.of()),
                refreshToken.map(OAuth2Authorization.Token::getToken).map(AbstractOAuth2Token::getTokenValue).orElse(null),
                refreshToken.map(OAuth2Authorization.Token::getToken).map(AbstractOAuth2Token::getIssuedAt).orElse(null),
                refreshToken.map(this::getTokenExpiresAt).orElse(null),
                refreshToken.map(OAuth2Authorization.Token::getMetadata).map(this::writeJson).orElse(null)
        ));

        if (this.authorizationCodeParamAccessor.isInCodeRequest()) {
            final String copyGw2AccountIdsFromClientAuthorizationId = this.authorizationCodeParamAccessor.<String>getValue("COPY_FROM_CLIENT_AUTHORIZATION_ID").orElse(null);

            if (copyGw2AccountIdsFromClientAuthorizationId != null || this.authorizationCodeParamAccessor.isInConsentContext()) {
                try (AccountService.LoggingContext logging = this.accountService.log(accountId, Map.of("type", "AUTHORIZATION", "client_id", applicationClientId))) {
                    final Set<UUID> authorizedTokenGw2AccountIds;

                    if (copyGw2AccountIdsFromClientAuthorizationId != null) {
                        logging.log("Using API-Tokens of existing authorization for same client and scopes");
                        authorizedTokenGw2AccountIds = this.applicationClientAuthorizationTokenRepository.findAllByApplicationClientAuthorizationIdAndAccountId(copyGw2AccountIdsFromClientAuthorizationId, accountId).stream()
                                .map(ApplicationClientAuthorizationTokenEntity::gw2AccountId)
                                .collect(Collectors.toSet());
                    } else {
                        authorizedTokenGw2AccountIds = this.authorizationCodeParamAccessor.getAdditionalParameters()
                                .map(Map.Entry::getKey)
                                .filter((v) -> v.startsWith("token:"))
                                .map((v) -> v.replaceFirst("token:", ""))
                                .flatMap((v) -> {
                                    try {
                                        return Stream.of(UUID.fromString(v));
                                    } catch (IllegalArgumentException e) {
                                        return Stream.empty();
                                    }
                                })
                                .collect(Collectors.toSet());
                    }

                    if (authorizedTokenGw2AccountIds.isEmpty()) {
                        throw this.authorizationCodeParamAccessor.error(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED));
                    }

                    final List<ApplicationClientAuthorizationTokenEntity> tokensToAdd = new ArrayList<>(authorizedTokenGw2AccountIds.size());

                    for (UUID authorizedTokenGw2AccountId : authorizedTokenGw2AccountIds) {
                        tokensToAdd.add(new ApplicationClientAuthorizationTokenEntity(entity.id(), accountId, authorizedTokenGw2AccountId));
                    }

                    this.applicationClientAuthorizationTokenRepository.deleteAllByAccountIdAndApplicationClientAuthorizationId(accountId, entity.id());
                    this.applicationClientAuthorizationTokenRepository.saveAll(tokensToAdd);

                    logging.log(String.format("New authorization with name '%s' (id %s)", entity.displayName(), entity.id()));
                    logging.log(String.format("Authorized scopes for this authorization: %s", entity.authorizedScopes()));
                    logging.log(String.format("%d API-Tokens are authorized for this authorization", authorizedTokenGw2AccountIds.size()));
                }
            }
        }
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        this.applicationClientAuthorizationRepository.deleteByIdAndAccountId(authorization.getId(), UUID.fromString(authorization.getPrincipalName()));
    }

    @Override
    public OAuth2Authorization findById(String id) {
        throw new UnsupportedOperationException("findById should not be used");
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        final ApplicationClientAuthorizationEntity entity;

        if (tokenType == null) {
            entity = this.applicationClientAuthorizationRepository.findByAnyToken(token).orElse(null);
        } else {
            entity = switch (tokenType.getValue()) {
                case OAuth2ParameterNames.STATE -> this.applicationClientAuthorizationRepository.findByState(token).orElse(null);
                case OAuth2ParameterNames.CODE -> this.applicationClientAuthorizationRepository.findByAuthorizationCode(token).orElse(null);
                case OAuth2ParameterNames.ACCESS_TOKEN -> this.applicationClientAuthorizationRepository.findByAccessToken(token).orElse(null);
                case OAuth2ParameterNames.REFRESH_TOKEN -> this.applicationClientAuthorizationRepository.findByRefreshToken(token).orElse(null);
                default -> null;
            };
        }

        if (entity == null) {
            return null;
        }

        final RegisteredClient registeredClient = this.registeredClientRepository.findById(entity.applicationClientId().toString());

        if (registeredClient == null) {
            return null;
        }

        OAuth2Authorization.Builder builder = OAuth2Authorization
                .withRegisteredClient(registeredClient)
                .id(entity.id())
                .principalName(entity.accountId().toString())
                .authorizationGrantType(new AuthorizationGrantType(entity.authorizationGrantType()));

        final Map<String, Object> attributes = readJson(entity.attributes());

        if (entity.authorizedScopes() != null) {
            builder.authorizedScopes(entity.authorizedScopes());
        }

        builder.attributes((attrs) -> attrs.putAll(attributes));

        final String state = entity.state();
        if (StringUtils.hasText(state)) {
            builder.attribute(OAuth2ParameterNames.STATE, state);
        }

        // authorization code
        final String authorizationCodeValue = entity.authorizationCodeValue();
        if (authorizationCodeValue != null) {
            final OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(authorizationCodeValue, entity.authorizationCodeIssuedAt(), entity.authorizationCodeExpiresAt());
            final Map<String, Object> tokenMetadata = readJson(entity.authorizationCodeMetadata());

            builder.token(authorizationCode, (metadata) -> metadata.putAll(tokenMetadata));
        }

        // access token
        final String accessTokenValue = entity.accessTokenValue();
        if (accessTokenValue != null) {
            OAuth2AccessToken.TokenType accessTokenType = null;
            if (OAuth2AccessToken.TokenType.BEARER.getValue().equalsIgnoreCase(entity.accessTokenType())) {
                accessTokenType = OAuth2AccessToken.TokenType.BEARER;
            }

            Set<String> scopes = entity.accessTokenScopes();
            if (scopes == null) {
                scopes = Set.of();
            }

            final OAuth2AccessToken accessToken = new OAuth2AccessToken(accessTokenType, accessTokenValue, entity.accessTokenIssuedAt(), entity.accessTokenExpiresAt(), scopes);
            final Map<String, Object> tokenMetadata = readJson(entity.accessTokenMetadata());

            builder.token(accessToken, (metadata) -> metadata.putAll(tokenMetadata));
        }

        // refresh token
        final String refreshTokenValue = entity.refreshTokenValue();
        if (refreshTokenValue != null) {
            final OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(refreshTokenValue, entity.refreshTokenIssuedAt(), entity.refreshTokenExpiresAt());
            final Map<String, Object> tokenMetadata = readJson(entity.refreshTokenMetadata());

            builder.token(refreshToken, (metadata) -> metadata.putAll(tokenMetadata));
        }

        return builder.build();
    }

    private Instant getTokenExpiresAt(OAuth2Authorization.Token<?> token) {
        final Instant expiresAt;

        if (token.isInvalidated()) {
            final Instant now = this.clock.instant();
            final Instant issuedAt = token.getToken().getIssuedAt();

            if (issuedAt == null || now.isAfter(issuedAt)) {
                expiresAt = now;
            } else {
                expiresAt = issuedAt;
            }
        } else {
            expiresAt = token.getToken().getExpiresAt();
        }

        return expiresAt;
    }

    private String writeJson(Map<String, Object> object) {
        try {
            return this.objectMapper.writeValueAsString(object);
        } catch (IOException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }

    private Map<String, Object> readJson(String data) {
        try {
            return this.objectMapper.readValue(data, new TypeReference<Map<String, Object>>() {});
        } catch (Exception ex) {
            throw new IllegalArgumentException(ex.getMessage(), ex);
        }
    }
    // endregion

    @Scheduled(fixedRate = 30L, timeUnit = TimeUnit.MINUTES)
    public void deleteAllExpiredAuthorizations() {
        final int deleted = this.applicationClientAuthorizationRepository.deleteAllExpired(this.clock.instant());
        LOG.info("scheduled deletion of expired authorizations deleted {} rows", deleted);
    }
}
