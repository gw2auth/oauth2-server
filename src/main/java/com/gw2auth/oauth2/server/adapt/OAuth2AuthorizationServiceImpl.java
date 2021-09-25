package com.gw2auth.oauth2.server.adapt;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gw2auth.oauth2.server.service.client.authorization.ClientAuthorizationService;
import com.gw2auth.oauth2.server.util.Utils;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUser;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUserMixin;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.ResultSetExtractor;
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
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class OAuth2AuthorizationServiceImpl implements OAuth2AuthorizationService {

    private static final String TABLE_NAME = "oauth2_authorization";
    private static final String[] COLUMNS = new String[]{
            "account_id", "client_registration_id", "id", "authorization_grant_type", "attributes", "state",
            "authorization_code_value", "authorization_code_issued_at", "authorization_code_expires_at", "authorization_code_metadata",
            "access_token_value", "access_token_issued_at", "access_token_expires_at", "access_token_metadata", "access_token_type", "access_token_scopes",
            "refresh_token_value", "refresh_token_issued_at", "refresh_token_expires_at", "refresh_token_metadata"
    };
    private static final String SAVE_AUTHORIZATION_SQL = "INSERT INTO " + TABLE_NAME +
            " (" + String.join(",", COLUMNS) + " )" +
            " VALUES" +
            " (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)" +
            " ON CONFLICT (account_id, client_registration_id) DO UPDATE SET " + Utils.upsertStatement(COLUMNS, 2);
    
    private static final String REMOVE_AUTHORIZATION_SQL = "DELETE FROM " + TABLE_NAME + " WHERE account_id = ? AND client_registration_id = ?";
    private static final String LOAD_AUTHORIZATION_SQL = "SELECT " + String.join(",", COLUMNS) +
            " FROM " + TABLE_NAME +
            " WHERE ";

    private final JdbcOperations jdbcOperations;
    private final RegisteredClientRepository registeredClientRepository;
    private final ClientAuthorizationService clientAuthorizationService;
    private final ObjectMapper objectMapper;
    private final ResultSetExtractor<OAuth2Authorization> resultSetExtractor;

    @Autowired
    public OAuth2AuthorizationServiceImpl(JdbcOperations jdbcOperations, RegisteredClientRepository registeredClientRepository, ClientAuthorizationService clientAuthorizationService) {
        this.jdbcOperations = jdbcOperations;
        this.registeredClientRepository = registeredClientRepository;
        this.clientAuthorizationService = clientAuthorizationService;

        this.objectMapper = new ObjectMapper();
        final ClassLoader classLoader = OAuth2AuthorizationServiceImpl.class.getClassLoader();
        final List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        this.objectMapper.registerModules(securityModules);
        this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
        this.objectMapper.addMixIn(Gw2AuthUser.class, Gw2AuthUserMixin.class);

        this.resultSetExtractor = new OAuth2AuthorizationResultSetExtractor();
    }

    @Override
    @Transactional
    public void save(OAuth2Authorization authorization) {
        final long accountId = Long.parseLong(authorization.getPrincipalName());
        final long registeredClientId = Long.parseLong(authorization.getRegisteredClientId());

        this.clientAuthorizationService.createEmptyClientAuthorizationIfNotExists(accountId, registeredClientId);

        this.jdbcOperations.update(SAVE_AUTHORIZATION_SQL, (ps) -> {
            final Idx idx = new Idx();

            ps.setLong(idx.next(), accountId);
            ps.setLong(idx.next(), registeredClientId);
            ps.setString(idx.next(), authorization.getId());
            ps.setString(idx.next(), authorization.getAuthorizationGrantType().getValue());
            ps.setString(idx.next(), writeJson(authorization.getAttributes()));

            String state = null;
            String authorizationState = authorization.getAttribute(OAuth2ParameterNames.STATE);
            if (StringUtils.hasText(authorizationState)) {
                state = authorizationState;
            }

            ps.setString(idx.next(), state);

            // authorization code
            setToken(ps, idx, authorization.getToken(OAuth2AuthorizationCode.class));

            // access token
            final OAuth2Authorization.Token<OAuth2AccessToken> accessToken = authorization.getAccessToken();
            setToken(ps, idx, accessToken);

            String accessTokenType = null;
            Array accessTokenScopes = null;
            if (accessToken != null) {
                accessTokenType = accessToken.getToken().getTokenType().getValue();
                if (!CollectionUtils.isEmpty(accessToken.getToken().getScopes())) {
                    accessTokenScopes = ps.getConnection().createArrayOf("VARCHAR", accessToken.getToken().getScopes().toArray(String[]::new));
                }
            }

            ps.setString(idx.next(), accessTokenType);
            ps.setArray(idx.next(), accessTokenScopes);

            // refresh token
            setToken(ps, idx, authorization.getRefreshToken());
        });
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        final long accountId = Long.parseLong(authorization.getPrincipalName());
        final long registeredClientId = Long.parseLong(authorization.getRegisteredClientId());

        removeByAccountIdAndClientRegistrationId(accountId, registeredClientId);
    }

    @Override
    public OAuth2Authorization findById(String id) {
        throw new UnsupportedOperationException("findById should not be used");
        // return findBy("id = ?", (ps) -> ps.setString(1, id));
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        if (tokenType == null) {
            return findBy("state = ? OR authorization_code_value = ? OR access_token_value = ? OR refresh_token_value = ?", (ps) -> {
                final byte[] bytes = token.getBytes(StandardCharsets.UTF_8);
                
                ps.setString(1, token);
                ps.setBytes(2, bytes);
                ps.setBytes(3, bytes);
                ps.setBytes(4, bytes);
            });
        } else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
            return findBy("state = ?", (ps) -> ps.setString(1, token));
        } else {
            final byte[] bytes = token.getBytes(StandardCharsets.UTF_8);
            final PreparedStatementSetter pss = (ps) -> ps.setBytes(1, bytes);
            
            if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
                return findBy("authorization_code_value = ?", pss);
            } else if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
                return findBy("access_token_value = ?", pss);
            } else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
                return findBy("refresh_token_value = ?", pss);
            } else {
                return null;
            }
        }
    }

    private void removeByAccountIdAndClientRegistrationId(long accountId, long clientRegistrationId) {
        this.jdbcOperations.update(REMOVE_AUTHORIZATION_SQL, accountId, clientRegistrationId);
    }
    
    private OAuth2Authorization findBy(String filter, PreparedStatementSetter pss) {
        return this.jdbcOperations.query(LOAD_AUTHORIZATION_SQL + filter, pss, this.resultSetExtractor);
    }

    private String writeJson(Object object) {
        try {
            return this.objectMapper.writeValueAsString(object);
        } catch (IOException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }

    private <T extends AbstractOAuth2Token> void setToken(PreparedStatement ps, Idx idx, OAuth2Authorization.Token<T> token) throws SQLException {
        byte[] tokenValue = null;
        Timestamp tokenIssuedAt = null;
        Timestamp tokenExpiresAt = null;
        String metadata = null;

        if (token != null) {
            tokenValue = token.getToken().getTokenValue().getBytes(StandardCharsets.UTF_8);
            if (token.getToken().getIssuedAt() != null) {
                tokenIssuedAt = Timestamp.from(token.getToken().getIssuedAt());
            }
            if (token.getToken().getExpiresAt() != null) {
                tokenExpiresAt = Timestamp.from(token.getToken().getExpiresAt());
            }

            metadata = writeJson(token.getMetadata());
        }

        ps.setBytes(idx.next(), tokenValue);
        ps.setTimestamp(idx.next(), tokenIssuedAt);
        ps.setTimestamp(idx.next(), tokenExpiresAt);
        ps.setString(idx.next(), metadata);
    }

    private class OAuth2AuthorizationResultSetExtractor implements ResultSetExtractor<OAuth2Authorization> {

        @Override
        public OAuth2Authorization extractData(ResultSet rs) throws SQLException, DataAccessException {
            if (!rs.next()) {
                return null;
            }
            
            final Idx idx = new Idx();

            final long accountId = rs.getLong(idx.next());
            final long registeredClientId = rs.getLong(idx.next());
            final String id = rs.getString(idx.next());

            final RegisteredClient registeredClient = OAuth2AuthorizationServiceImpl.this.registeredClientRepository.findById(Long.toString(registeredClientId));

            if (registeredClient == null) {
                OAuth2AuthorizationServiceImpl.this.removeByAccountIdAndClientRegistrationId(accountId, registeredClientId);
                throw new DataRetrievalFailureException("The RegisteredClient with id '" + registeredClientId + "' was not found in the RegisteredClientRepository.");
            }
            
            OAuth2Authorization.Builder builder = OAuth2Authorization
                    .withRegisteredClient(registeredClient)
                    .id(id)
                    .principalName(Long.toString(accountId))
                    .authorizationGrantType(new AuthorizationGrantType(rs.getString(idx.next())));
            
            final Map<String, Object> attributes = readJson(rs.getString(idx.next()));
            builder.attributes((attrs) -> attrs.putAll(attributes));
            
            final String state = rs.getString(idx.next());
            if (StringUtils.hasText(state)) {
                builder.attribute(OAuth2ParameterNames.STATE, state);
            }

            // authorization code
            getToken(rs, idx, (tokenValue, tokenIssuedAt, tokenExpiresAt, tokenMetadata) -> {
                final OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(tokenValue, tokenIssuedAt, tokenExpiresAt);
                builder.token(authorizationCode, (metadata) -> metadata.putAll(tokenMetadata));
            });

            // access token
            final boolean accessTokenRead = getToken(rs, idx, (tokenValue, tokenIssuedAt, tokenExpiresAt, tokenMetadata) -> {
                OAuth2AccessToken.TokenType tokenType = null;
                if (OAuth2AccessToken.TokenType.BEARER.getValue().equalsIgnoreCase(rs.getString(idx.next()))) {
                    tokenType = OAuth2AccessToken.TokenType.BEARER;
                }

                Set<String> scopes = Collections.emptySet();
                Array accessTokenScopes = rs.getArray(idx.next());
                if (accessTokenScopes != null) {
                    scopes = Utils.collectSQLArray(accessTokenScopes, ResultSet::getString, Collectors.toSet());
                }

                final OAuth2AccessToken accessToken = new OAuth2AccessToken(tokenType, tokenValue, tokenIssuedAt, tokenExpiresAt, scopes);
                builder.token(accessToken, (metadata) -> metadata.putAll(tokenMetadata));
            });

            if (!accessTokenRead) {
                // skip tokentype and scopes
                idx.incr(2);
            }

            // refresh token
            getToken(rs, idx, (tokenValue, tokenIssuedAt, tokenExpiresAt, tokenMetadata) -> {
                OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(tokenValue, tokenIssuedAt, tokenExpiresAt);
                builder.token(refreshToken, (metadata) -> metadata.putAll(tokenMetadata));
            });
            
            return builder.build();
        }

        private Map<String, Object> readJson(String data) {
            try {
                return OAuth2AuthorizationServiceImpl.this.objectMapper.readValue(data, new TypeReference<Map<String, Object>>() {});
            } catch (Exception ex) {
                throw new IllegalArgumentException(ex.getMessage(), ex);
            }
        }
        
        private boolean getToken(ResultSet rs, Idx idx, TokenAttributesConsumer tokenAttributesConsumer) throws SQLException {
            final byte[] tokenValue = rs.getBytes(idx.next());
            if (tokenValue != null) {
                final Instant tokenIssuedAt = Optional.ofNullable(rs.getTimestamp(idx.next())).map(Timestamp::toInstant).orElse(null);
                final Instant tokenExpiresAt = Optional.ofNullable(rs.getTimestamp(idx.next())).map(Timestamp::toInstant).orElse(null);
                final Map<String, Object> tokenMetadata = readJson(rs.getString(idx.next()));
                
                tokenAttributesConsumer.accept(new String(tokenValue, StandardCharsets.UTF_8), tokenIssuedAt, tokenExpiresAt, tokenMetadata);
                return true;
            } else {
                // skip the next 3 parameters for this token
                idx.incr(3);
                return false;
            }
        }
    }
    
    private static class Idx {
        
        private int value;
        
        public int next() {
            return ++this.value;
        }

        public void incr(int delta) {
            this.value += delta;
        }
    }

    @FunctionalInterface
    private interface TokenAttributesConsumer {

        void accept(String tokenValue, Instant tokenIssuedAt, Instant tokenExpiresAt, Map<String, Object> tokenMetadata) throws SQLException;
    }
}
