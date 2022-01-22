package com.gw2auth.oauth2.server.service.client.authorization;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gw2auth.oauth2.server.adapt.Java9CollectionJackson2Module;
import com.gw2auth.oauth2.server.adapt.LinkedHashSetJackson2Module;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationEntity;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationRepository;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationTokenEntity;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationTokenRepository;
import com.gw2auth.oauth2.server.service.client.AuthorizationCodeParamAccessor;
import com.gw2auth.oauth2.server.service.client.consent.ClientConsentService;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUser;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUserMixin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
@EnableScheduling
public class ClientAuthorizationServiceImpl implements ClientAuthorizationService, OAuth2AuthorizationService {

    private static final Logger LOG = LoggerFactory.getLogger(ClientAuthorizationServiceImpl.class);

    private final ClientAuthorizationRepository clientAuthorizationRepository;
    private final ClientAuthorizationTokenRepository clientAuthorizationTokenRepository;
    private final ClientConsentService clientConsentService;
    private final RegisteredClientRepository registeredClientRepository;
    private final AuthorizationCodeParamAccessor authorizationCodeParamAccessor;
    private final ObjectMapper objectMapper;

    public ClientAuthorizationServiceImpl(ClientAuthorizationRepository clientAuthorizationRepository,
                                          ClientAuthorizationTokenRepository clientAuthorizationTokenRepository,
                                          ClientConsentService clientConsentService,
                                          RegisteredClientRepository registeredClientRepository,
                                          AuthorizationCodeParamAccessor authorizationCodeParamAccessor) {

        this.clientAuthorizationRepository = clientAuthorizationRepository;
        this.clientAuthorizationTokenRepository = clientAuthorizationTokenRepository;
        this.clientConsentService = clientConsentService;
        this.registeredClientRepository = registeredClientRepository;
        this.authorizationCodeParamAccessor = authorizationCodeParamAccessor;
        this.objectMapper = new ObjectMapper();

        final ClassLoader classLoader = ClientAuthorizationServiceImpl.class.getClassLoader();
        final List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        this.objectMapper.registerModules(securityModules);
        this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
        this.objectMapper.registerModule(new Java9CollectionJackson2Module());
        this.objectMapper.registerModule(new LinkedHashSetJackson2Module());
        this.objectMapper.addMixIn(Gw2AuthUser.class, Gw2AuthUserMixin.class);
    }

    @Autowired
    public ClientAuthorizationServiceImpl(ClientAuthorizationRepository clientAuthorizationRepository,
                                          ClientAuthorizationTokenRepository clientAuthorizationTokenRepository,
                                          ClientConsentService clientConsentService,
                                          RegisteredClientRepository registeredClientRepository) {

        this(clientAuthorizationRepository, clientAuthorizationTokenRepository, clientConsentService, registeredClientRepository, AuthorizationCodeParamAccessor.DEFAULT);
    }

    @Override
    public Optional<ClientAuthorization> getClientAuthorization(long accountId, String id) {
        return this.clientAuthorizationRepository.findByAccountIdAndId(accountId, id)
                .filter(ClientAuthorizationServiceImpl::isValidAuthorization)
                .flatMap((entity) -> {
                    final List<ClientAuthorizationTokenEntity> clientAuthorizationTokenEntities = this.clientAuthorizationTokenRepository.findAllByAccountIdAndClientAuthorizationId(entity.accountId(), entity.id());

                    if (clientAuthorizationTokenEntities.isEmpty()) {
                        return Optional.empty();
                    } else {
                        return Optional.of(ClientAuthorization.fromEntity(entity, clientAuthorizationTokenEntities));
                    }
                });
    }

    @Override
    public List<ClientAuthorization> getClientAuthorizations(long accountId, String clientId) {
        final List<ClientAuthorizationEntity> clientAuthorizationEntities = this.clientAuthorizationRepository.findAllByAccountIdAndClientId(accountId, clientId).stream()
                .filter(ClientAuthorizationServiceImpl::isValidAuthorization)
                .toList();

        final Set<String> clientAuthorizationIds = clientAuthorizationEntities.stream()
                .map(ClientAuthorizationEntity::id)
                .collect(Collectors.toSet());

        final Map<String, List<ClientAuthorizationTokenEntity>> clientAuthorizationTokenEntitiesByAuthorizationId = this.clientAuthorizationTokenRepository.findAllByAccountIdAndClientAuthorizationIds(accountId, clientAuthorizationIds).stream()
                .collect(Collectors.groupingBy(ClientAuthorizationTokenEntity::clientAuthorizationId));

        final List<ClientAuthorization> result = new ArrayList<>(clientAuthorizationEntities.size());

        for (ClientAuthorizationEntity clientAuthorizationEntity : clientAuthorizationEntities) {
            final List<ClientAuthorizationTokenEntity> clientAuthorizationTokenEntities = clientAuthorizationTokenEntitiesByAuthorizationId.get(clientAuthorizationEntity.id());

            if (clientAuthorizationTokenEntities != null && !clientAuthorizationTokenEntities.isEmpty()) {
                result.add(ClientAuthorization.fromEntity(clientAuthorizationEntity, clientAuthorizationTokenEntities));
            }
        }

        return result;
    }

    @Override
    public List<ClientAuthorization> getClientAuthorizations(long accountId, Set<String> gw2AccountIds) {
        final Map<String, ClientAuthorizationEntity> clientAuthorizationEntities = this.clientAuthorizationRepository.findAllByAccountIdAndLinkedTokens(accountId, gw2AccountIds).stream()
                .filter(ClientAuthorizationServiceImpl::isValidAuthorization)
                .collect(Collectors.toMap(ClientAuthorizationEntity::id, Function.identity()));

        final Map<String, List<ClientAuthorizationTokenEntity>> clientAuthorizationTokenEntities = this.clientAuthorizationTokenRepository.findAllByAccountIdAndClientAuthorizationIds(accountId, clientAuthorizationEntities.keySet()).stream()
                .collect(Collectors.groupingBy(ClientAuthorizationTokenEntity::clientAuthorizationId));

        final List<ClientAuthorization> result = new ArrayList<>(clientAuthorizationEntities.size());

        for (Map.Entry<String, ClientAuthorizationEntity> entry : clientAuthorizationEntities.entrySet()) {
            final List<ClientAuthorizationTokenEntity> tokens = clientAuthorizationTokenEntities.get(entry.getKey());

            if (tokens != null && !tokens.isEmpty()) {
                result.add(ClientAuthorization.fromEntity(entry.getValue(), tokens));
            }
        }

        return result;
    }

    @Override
    public boolean deleteClientAuthorization(long accountId, String id) {
        return this.clientAuthorizationRepository.deleteByAccountIdAndId(accountId, id);
    }

    public static boolean isValidAuthorization(ClientAuthorizationEntity entity) {
        return entity.authorizedScopes() != null && !entity.authorizedScopes().isEmpty();
    }

    // region OAuth2AuthorizationService
    @Override
    @Transactional
    public void save(OAuth2Authorization authorization) {
        final long accountId = Long.parseLong(authorization.getPrincipalName());
        final long clientRegistrationId = Long.parseLong(authorization.getRegisteredClientId());

        if (authorization.getRefreshToken() != null && Boolean.TRUE.equals(authorization.getRefreshToken().getMetadata(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME))) {
            deleteClientAuthorization(accountId, authorization.getId());
            return;
        }

        this.clientConsentService.createEmptyClientConsentIfNotExists(accountId, clientRegistrationId);

        final Optional<OAuth2Authorization.Token<OAuth2AuthorizationCode>> authorizationCode = Optional.ofNullable(authorization.getToken(OAuth2AuthorizationCode.class));
        final Optional<OAuth2Authorization.Token<OAuth2AccessToken>> accessToken = Optional.ofNullable(authorization.getAccessToken());
        final Optional<OAuth2Authorization.Token<OAuth2RefreshToken>> refreshToken = Optional.ofNullable(authorization.getRefreshToken());

        final Map<String, Object> attributes = new HashMap<>(authorization.getAttributes());
        final Set<String> authorizedScopes = authorization.getAttribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME);
        attributes.remove(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME);

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

        final Instant now = Instant.now();

        final ClientAuthorizationEntity clientAuthorizationEntity = this.clientAuthorizationRepository.save(new ClientAuthorizationEntity(
                accountId,
                authorization.getId(),
                clientRegistrationId,
                now,
                now,
                Optional.ofNullable(name).orElse(authorization.getId()),
                authorization.getAuthorizationGrantType().getValue(),
                Optional.ofNullable(authorizedScopes).orElse(Set.of()),
                writeJson(attributes),
                authorization.getAttribute(OAuth2ParameterNames.STATE),
                authorizationCode.map(OAuth2Authorization.Token::getToken).map(AbstractOAuth2Token::getTokenValue).orElse(null),
                authorizationCode.map(OAuth2Authorization.Token::getToken).map(AbstractOAuth2Token::getIssuedAt).orElse(null),
                authorizationCode.map(OAuth2Authorization.Token::getToken).map(AbstractOAuth2Token::getExpiresAt).orElse(null),
                authorizationCode.map(OAuth2Authorization.Token::getMetadata).map(this::writeJson).orElse(null),
                accessToken.map(OAuth2Authorization.Token::getToken).map(AbstractOAuth2Token::getTokenValue).orElse(null),
                accessToken.map(OAuth2Authorization.Token::getToken).map(AbstractOAuth2Token::getIssuedAt).orElse(null),
                accessToken.map(OAuth2Authorization.Token::getToken).map(AbstractOAuth2Token::getExpiresAt).orElse(null),
                accessToken.map(OAuth2Authorization.Token::getMetadata).map(this::writeJson).orElse(null),
                accessToken.map(OAuth2Authorization.Token::getToken).map((v) -> v.getTokenType().getValue()).orElse(null),
                accessToken.map(OAuth2Authorization.Token::getToken).map(OAuth2AccessToken::getScopes).orElse(Set.of()),
                refreshToken.map(OAuth2Authorization.Token::getToken).map(AbstractOAuth2Token::getTokenValue).orElse(null),
                refreshToken.map(OAuth2Authorization.Token::getToken).map(AbstractOAuth2Token::getIssuedAt).orElse(null),
                refreshToken.map(OAuth2Authorization.Token::getToken).map(AbstractOAuth2Token::getExpiresAt).orElse(null),
                refreshToken.map(OAuth2Authorization.Token::getMetadata).map(this::writeJson).orElse(null)
        ));

        if (this.authorizationCodeParamAccessor.isInCodeRequest()) {
            final String copyGw2AccountIdsFromClientAuthorizationId = this.authorizationCodeParamAccessor.<String>getValue("COPY_FROM_CLIENT_AUTHORIZATION_ID").orElse(null);

            if (copyGw2AccountIdsFromClientAuthorizationId != null || this.authorizationCodeParamAccessor.isInConsentContext()) {
                try (ClientConsentService.LoggingContext logging = this.clientConsentService.log(accountId, clientRegistrationId, ClientConsentService.LogType.AUTHORIZATION)) {
                    final Set<String> authorizedTokenGw2AccountIds;

                    if (copyGw2AccountIdsFromClientAuthorizationId != null) {
                        logging.log("Using API-Tokens of existing authorization for same client and scopes");
                        authorizedTokenGw2AccountIds = this.clientAuthorizationTokenRepository.findAllByAccountIdAndClientAuthorizationId(accountId, copyGw2AccountIdsFromClientAuthorizationId).stream()
                                .map(ClientAuthorizationTokenEntity::gw2AccountId)
                                .collect(Collectors.toSet());
                    } else {
                        authorizedTokenGw2AccountIds = this.authorizationCodeParamAccessor.getAdditionalParameters()
                                .map(Map.Entry::getKey)
                                .filter((v) -> v.startsWith("token:"))
                                .map((v) -> v.replaceFirst("token:", ""))
                                .collect(Collectors.toSet());
                    }

                    if (authorizedTokenGw2AccountIds.isEmpty()) {
                        throw this.authorizationCodeParamAccessor.error(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED));
                    }

                    final List<ClientAuthorizationTokenEntity> tokensToAdd = new ArrayList<>(authorizedTokenGw2AccountIds.size());

                    for (String authorizedTokenGw2AccountId : authorizedTokenGw2AccountIds) {
                        tokensToAdd.add(new ClientAuthorizationTokenEntity(accountId, clientAuthorizationEntity.id(), authorizedTokenGw2AccountId));
                    }

                    this.clientAuthorizationTokenRepository.deleteAllByAccountIdAndClientAuthorizationId(accountId, clientAuthorizationEntity.id());
                    this.clientAuthorizationTokenRepository.saveAll(tokensToAdd);

                    logging.log("New authorization with name '%s' (id %s)", clientAuthorizationEntity.displayName(), clientAuthorizationEntity.id());
                    logging.log("Authorized scopes for this authorization: %s", clientAuthorizationEntity.authorizedScopes());
                    logging.log("%d API-Tokens are authorized for this authorization", authorizedTokenGw2AccountIds.size());
                }
            }
        }
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        this.clientAuthorizationRepository.deleteByAccountIdAndId(Long.parseLong(authorization.getPrincipalName()), authorization.getId());
    }

    @Override
    public OAuth2Authorization findById(String id) {
        throw new UnsupportedOperationException("findById should not be used");
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        final ClientAuthorizationEntity clientAuthorizationEntity;

        if (tokenType == null) {
            clientAuthorizationEntity = this.clientAuthorizationRepository.findByAnyToken(token).orElse(null);
        } else {
            clientAuthorizationEntity = switch (tokenType.getValue()) {
                case OAuth2ParameterNames.STATE -> this.clientAuthorizationRepository.findByState(token).orElse(null);
                case OAuth2ParameterNames.CODE -> this.clientAuthorizationRepository.findByAuthorizationCode(token).orElse(null);
                case OAuth2ParameterNames.ACCESS_TOKEN -> this.clientAuthorizationRepository.findByAccessToken(token).orElse(null);
                case OAuth2ParameterNames.REFRESH_TOKEN -> this.clientAuthorizationRepository.findByRefreshToken(token).orElse(null);
                default -> null;
            };
        }

        if (clientAuthorizationEntity == null) {
            return null;
        }

        final RegisteredClient registeredClient = this.registeredClientRepository.findById(Long.toString(clientAuthorizationEntity.clientRegistrationId()));

        if (registeredClient == null) {
            return null;
        }

        OAuth2Authorization.Builder builder = OAuth2Authorization
                .withRegisteredClient(registeredClient)
                .id(clientAuthorizationEntity.id())
                .principalName(Long.toString(clientAuthorizationEntity.accountId()))
                .authorizationGrantType(new AuthorizationGrantType(clientAuthorizationEntity.authorizationGrantType()));

        final Map<String, Object> attributes = readJson(clientAuthorizationEntity.attributes());

        if (clientAuthorizationEntity.authorizedScopes() != null) {
            attributes.put(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME, clientAuthorizationEntity.authorizedScopes());
        }

        builder.attributes((attrs) -> attrs.putAll(attributes));

        final String state = clientAuthorizationEntity.state();
        if (StringUtils.hasText(state)) {
            builder.attribute(OAuth2ParameterNames.STATE, state);
        }

        // authorization code
        final String authorizationCodeValue = clientAuthorizationEntity.authorizationCodeValue();
        if (authorizationCodeValue != null) {
            final OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(authorizationCodeValue, clientAuthorizationEntity.authorizationCodeIssuedAt(), clientAuthorizationEntity.authorizationCodeExpiresAt());
            final Map<String, Object> tokenMetadata = readJson(clientAuthorizationEntity.authorizationCodeMetadata());

            builder.token(authorizationCode, (metadata) -> metadata.putAll(tokenMetadata));
        }

        // access token
        final String accessTokenValue = clientAuthorizationEntity.accessTokenValue();
        if (accessTokenValue != null) {
            OAuth2AccessToken.TokenType accessTokenType = null;
            if (OAuth2AccessToken.TokenType.BEARER.getValue().equalsIgnoreCase(clientAuthorizationEntity.accessTokenType())) {
                accessTokenType = OAuth2AccessToken.TokenType.BEARER;
            }

            Set<String> scopes = clientAuthorizationEntity.accessTokenScopes();
            if (scopes == null) {
                scopes = Set.of();
            }

            final OAuth2AccessToken accessToken = new OAuth2AccessToken(accessTokenType, accessTokenValue, clientAuthorizationEntity.accessTokenIssuedAt(), clientAuthorizationEntity.accessTokenExpiresAt(), scopes);
            final Map<String, Object> tokenMetadata = readJson(clientAuthorizationEntity.accessTokenMetadata());

            builder.token(accessToken, (metadata) -> metadata.putAll(tokenMetadata));
        }

        // refresh token
        final String refreshTokenValue = clientAuthorizationEntity.refreshTokenValue();
        if (refreshTokenValue != null) {
            final OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(refreshTokenValue, clientAuthorizationEntity.refreshTokenIssuedAt(), clientAuthorizationEntity.refreshTokenExpiresAt());
            final Map<String, Object> tokenMetadata = readJson(clientAuthorizationEntity.refreshTokenMetadata());

            builder.token(refreshToken, (metadata) -> metadata.putAll(tokenMetadata));
        }

        return builder.build();
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

    @Scheduled(fixedRate = 1000L * 60L * 5L)
    public void deleteAllExpiredAuthorizations() {
        final int deleted = this.clientAuthorizationRepository.deleteAllExpired();
        LOG.info("scheduled deletion of expired authorizations deleted {} rows", deleted);
    }
}
