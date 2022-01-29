package com.gw2auth.oauth2.server.repository.client.authorization;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.springframework.data.jdbc.repository.query.Modifying;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

@Repository
public interface ClientAuthorizationRepository extends BaseRepository<ClientAuthorizationEntity> {

    @Override
    default ClientAuthorizationEntity save(ClientAuthorizationEntity entity) {
        return save(
                entity.accountId(),
                entity.id(),
                entity.clientRegistrationId(),
                entity.creationTime(),
                entity.lastUpdateTime(),
                entity.displayName(),
                entity.authorizationGrantType(),
                entity.authorizedScopes(),
                entity.attributes(),
                entity.state(),
                entity.authorizationCodeValue(),
                entity.authorizationCodeIssuedAt(),
                entity.authorizationCodeExpiresAt(),
                entity.authorizationCodeMetadata(),
                entity.accessTokenValue(),
                entity.accessTokenIssuedAt(),
                entity.accessTokenExpiresAt(),
                entity.accessTokenMetadata(),
                entity.accessTokenType(),
                entity.accessTokenScopes(),
                entity.refreshTokenValue(),
                entity.refreshTokenIssuedAt(),
                entity.refreshTokenExpiresAt(),
                entity.refreshTokenMetadata()
        );
    }

    @Query("""
    INSERT INTO client_authorizations
    (account_id, id, client_registration_id, creation_time, last_update_time, display_name, authorization_grant_type, authorized_scopes, attributes, state, authorization_code_value, authorization_code_issued_at, authorization_code_expires_at, authorization_code_metadata, access_token_value, access_token_issued_at, access_token_expires_at, access_token_metadata, access_token_type, access_token_scopes, refresh_token_value, refresh_token_issued_at, refresh_token_expires_at, refresh_token_metadata)
    VALUES
    (:account_id, :id, :client_registration_id, :creation_time, :last_update_time, :display_name, :authorization_grant_type, ARRAY[ :authorized_scopes ]::TEXT[], :attributes, :state, :authorization_code_value, :authorization_code_issued_at, :authorization_code_expires_at, :authorization_code_metadata, :access_token_value, :access_token_issued_at, :access_token_expires_at, :access_token_metadata, :access_token_type, ARRAY[ :access_token_scopes ]::TEXT[], :refresh_token_value, :refresh_token_issued_at, :refresh_token_expires_at, :refresh_token_metadata)
    ON CONFLICT (account_id, id) DO UPDATE SET
    last_update_time = EXCLUDED.last_update_time,
    display_name = CASE
        WHEN EXCLUDED.display_name = EXCLUDED.id THEN client_authorizations.display_name
        ELSE EXCLUDED.display_name
    END,
    authorization_grant_type = EXCLUDED.authorization_grant_type,
    authorized_scopes = EXCLUDED.authorized_scopes,
    attributes = EXCLUDED.attributes,
    state = EXCLUDED.state,
    authorization_code_value = EXCLUDED.authorization_code_value,
    authorization_code_issued_at = EXCLUDED.authorization_code_issued_at,
    authorization_code_expires_at = EXCLUDED.authorization_code_expires_at,
    authorization_code_metadata = EXCLUDED.authorization_code_metadata,
    access_token_value = EXCLUDED.access_token_value,
    access_token_issued_at = EXCLUDED.access_token_issued_at,
    access_token_expires_at = EXCLUDED.access_token_expires_at,
    access_token_metadata = EXCLUDED.access_token_metadata,
    access_token_type = EXCLUDED.access_token_type,
    access_token_scopes = EXCLUDED.access_token_scopes,
    refresh_token_value = EXCLUDED.refresh_token_value,
    refresh_token_issued_at = EXCLUDED.refresh_token_issued_at,
    refresh_token_expires_at = EXCLUDED.refresh_token_expires_at,
    refresh_token_metadata = EXCLUDED.refresh_token_metadata
    RETURNING *
    """)
    ClientAuthorizationEntity save(@Param("account_id") long accountId,
                                   @Param("id") String id,
                                   @Param("client_registration_id") long clientRegistrationId,
                                   @Param("creation_time") Instant creationTime,
                                   @Param("last_update_time") Instant lastUpdateTime,
                                   @Param("display_name") String displayName,
                                   @Param("authorization_grant_type") String authorizationGrantType,
                                   @Param("authorized_scopes") Set<String> authorizedScopes,
                                   @Param("attributes") String attributes,
                                   @Param("state") String state,
                                   @Param("authorization_code_value") String authorizationCodeValue,
                                   @Param("authorization_code_issued_at") Instant authorizationCodeIssuedAt,
                                   @Param("authorization_code_expires_at") Instant authorizationCodeExpiresAt,
                                   @Param("authorization_code_metadata") String authorizationCodeMetadata,
                                   @Param("access_token_value") String accessTokenValue,
                                   @Param("access_token_issued_at") Instant accessTokenIssuedAt,
                                   @Param("access_token_expires_at") Instant accessTokenExpiresAt,
                                   @Param("access_token_metadata") String accessTokenMetadata,
                                   @Param("access_token_type") String accessTokenType,
                                   @Param("access_token_scopes") Set<String> accessTokenScopes,
                                   @Param("refresh_token_value") String refreshTokenValue,
                                   @Param("refresh_token_issued_at") Instant refreshTokenIssuedAt,
                                   @Param("refresh_token_expires_at") Instant refreshTokenExpiresAt,
                                   @Param("refresh_token_metadata") String refreshTokenMetadata);

    @Query("""
    SELECT *
    FROM client_authorizations
    WHERE state = :state
    """)
    Optional<ClientAuthorizationEntity> findByState(@Param("state") String state);

    @Query("""
    SELECT *
    FROM client_authorizations
    WHERE authorization_code_value = :authorization_code
    """)
    Optional<ClientAuthorizationEntity> findByAuthorizationCode(@Param("authorization_code") String authorizationCode);

    @Query("""
    SELECT *
    FROM client_authorizations
    WHERE access_token_value = :access_token
    """)
    Optional<ClientAuthorizationEntity> findByAccessToken(@Param("access_token") String accessToken);

    @Query("""
    SELECT *
    FROM client_authorizations
    WHERE refresh_token_value = :refresh_token
    """)
    Optional<ClientAuthorizationEntity> findByRefreshToken(@Param("refresh_token") String refreshToken);

    @Query("""
    SELECT *
    FROM client_authorizations
    WHERE state = :token OR authorization_code_value = :token OR access_token_value = :token OR refresh_token_value = :token
    LIMIT 1
    """)
    Optional<ClientAuthorizationEntity> findByAnyToken(@Param("token") String token);

    @Query("""
    SELECT *
    FROM client_authorizations
    WHERE account_id = :account_id AND id = :id
    """)
    Optional<ClientAuthorizationEntity> findByAccountIdAndId(@Param("account_id") long accountId, @Param("id") String id);

    @Query("""
    SELECT *
    FROM client_authorizations
    WHERE account_id = :account_id
    AND client_registration_id = :client_registration_id
    """)
    List<ClientAuthorizationEntity> findAllByAccountIdAndClientRegistrationId(@Param("account_id") long accountId, @Param("client_registration_id") long clientRegistrationId);

    @Query("""
    SELECT *
    FROM client_authorizations
    WHERE account_id = :account_id
    AND client_registration_id = :client_registration_id
    AND authorized_scopes @> ARRAY[ :authorized_scopes ]::TEXT[]
    ORDER BY creation_time DESC
    LIMIT 1
    """)
    Optional<ClientAuthorizationEntity> findLatestByAccountIdAndClientRegistrationIdAndHavingScopes(@Param("account_id") long accountId, @Param("client_registration_id") long clientRegistrationId, @Param("authorized_scopes") Set<String> scopes);

    @Query("""
    SELECT auth.*
    FROM client_authorizations auth
    INNER JOIN client_registrations reg
    ON auth.client_registration_id = reg.id
    WHERE auth.account_id = :account_id
    AND reg.client_id = :client_id
    """)
    List<ClientAuthorizationEntity> findAllByAccountIdAndClientId(@Param("account_id") long accountId, @Param("client_id") UUID clientId);

    @Query("""
    SELECT auth.*
    FROM client_authorizations auth
    INNER JOIN client_authorization_tokens auth_tk
    ON auth.account_id = auth_tk.account_id AND auth.id = auth_tk.client_authorization_id
    WHERE auth.account_id = :account_id AND auth_tk.gw2_account_id = ANY(ARRAY[ :gw2_account_ids ]::UUID[])
    GROUP BY auth.account_id, auth.id
    """)
    List<ClientAuthorizationEntity> findAllByAccountIdAndLinkedTokens(@Param("account_id") long accountId, @Param("gw2_account_ids") Set<UUID> gw2AccountIds);

    @Modifying
    @Query("DELETE FROM client_authorizations WHERE account_id = :account_id AND id = :id")
    boolean deleteByAccountIdAndId(@Param("account_id") long accountId, @Param("id") String id);

    @Modifying
    @Query("""
    DELETE FROM client_authorizations
    WHERE (refresh_token_value IS NOT NULL AND refresh_token_expires_at < NOW())
    OR (refresh_token_value IS NULL AND authorization_code_value IS NOT NULL AND authorization_code_expires_at < NOW())
    OR (refresh_token_value IS NULL AND authorization_code_value IS NULL AND (last_update_time + INTERVAL '30 MINUTES') < NOW())
    """)
    int deleteAllExpired();
}
