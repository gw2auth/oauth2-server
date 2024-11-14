package com.gw2auth.oauth2.server.repository.application.client.authorization;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.jspecify.annotations.Nullable;
import org.springframework.data.jdbc.repository.query.Modifying;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.*;

@Repository
public interface ApplicationClientAuthorizationRepository extends BaseRepository<ApplicationClientAuthorizationEntity> {

    @Override
    default ApplicationClientAuthorizationEntity save(ApplicationClientAuthorizationEntity entity) {
        return save(
                entity.id(),
                entity.accountId(),
                entity.applicationClientId(),
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
    INSERT INTO application_client_authorizations
    (id, account_id, application_client_id, creation_time, last_update_time, display_name, authorization_grant_type, authorized_scopes, attributes, state, authorization_code_value, authorization_code_issued_at, authorization_code_expires_at, authorization_code_metadata, access_token_value, access_token_issued_at, access_token_expires_at, access_token_metadata, access_token_type, access_token_scopes, refresh_token_value, refresh_token_issued_at, refresh_token_expires_at, refresh_token_metadata)
    VALUES
    (:id, :account_id, :application_client_id, :creation_time, :last_update_time, :display_name, :authorization_grant_type, ARRAY[ :authorized_scopes ]::TEXT[], :attributes, :state, :authorization_code_value, :authorization_code_issued_at, :authorization_code_expires_at, :authorization_code_metadata, :access_token_value, :access_token_issued_at, :access_token_expires_at, :access_token_metadata, :access_token_type, ARRAY[ :access_token_scopes ]::TEXT[], :refresh_token_value, :refresh_token_issued_at, :refresh_token_expires_at, :refresh_token_metadata)
    ON CONFLICT (id) DO UPDATE SET
    last_update_time = EXCLUDED.last_update_time,
    display_name = CASE
        WHEN EXCLUDED.display_name = EXCLUDED.id THEN application_client_authorizations.display_name
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
    ApplicationClientAuthorizationEntity save(@Param("id") String id,
                                              @Param("account_id") UUID accountId,
                                              @Param("application_client_id") UUID applicationClientId,
                                              @Param("creation_time") Instant creationTime,
                                              @Param("last_update_time") Instant lastUpdateTime,
                                              @Param("display_name") String displayName,
                                              @Param("authorization_grant_type") String authorizationGrantType,
                                              @Param("authorized_scopes") Set<String> authorizedScopes,
                                              @Param("attributes") @Nullable String attributes,
                                              @Param("state") @Nullable String state,
                                              @Param("authorization_code_value") @Nullable String authorizationCodeValue,
                                              @Param("authorization_code_issued_at") @Nullable Instant authorizationCodeIssuedAt,
                                              @Param("authorization_code_expires_at") @Nullable Instant authorizationCodeExpiresAt,
                                              @Param("authorization_code_metadata") @Nullable String authorizationCodeMetadata,
                                              @Param("access_token_value") @Nullable String accessTokenValue,
                                              @Param("access_token_issued_at") @Nullable Instant accessTokenIssuedAt,
                                              @Param("access_token_expires_at") @Nullable Instant accessTokenExpiresAt,
                                              @Param("access_token_metadata") @Nullable String accessTokenMetadata,
                                              @Param("access_token_type") @Nullable String accessTokenType,
                                              @Param("access_token_scopes") Set<String> accessTokenScopes,
                                              @Param("refresh_token_value") @Nullable String refreshTokenValue,
                                              @Param("refresh_token_issued_at") @Nullable Instant refreshTokenIssuedAt,
                                              @Param("refresh_token_expires_at") @Nullable Instant refreshTokenExpiresAt,
                                              @Param("refresh_token_metadata") @Nullable String refreshTokenMetadata);

    @Query("""
    SELECT *
    FROM application_client_authorizations
    WHERE state = :state
    """)
    Optional<ApplicationClientAuthorizationEntity> findByState(@Param("state") String state);

    // makes use of md5 index, then filter possible hash collisions
    @Query("""
    SELECT *
    FROM application_client_authorizations
    WHERE md5(authorization_code_value) = md5(:authorization_code)
    AND authorization_code_value = :authorization_code
    """)
    Optional<ApplicationClientAuthorizationEntity> findByAuthorizationCode(@Param("authorization_code") String authorizationCode);

    // makes use of md5 index, then filter possible hash collisions
    @Query("""
    SELECT *
    FROM application_client_authorizations
    WHERE md5(access_token_value) = md5(:access_token)
    AND access_token_value = :access_token
    """)
    Optional<ApplicationClientAuthorizationEntity> findByAccessToken(@Param("access_token") String accessToken);

    // makes use of md5 index, then filter possible hash collisions
    @Query("""
    SELECT *
    FROM application_client_authorizations
    WHERE md5(refresh_token_value) = md5(:refresh_token)
    AND refresh_token_value = :refresh_token
    """)
    Optional<ApplicationClientAuthorizationEntity> findByRefreshToken(@Param("refresh_token") String refreshToken);

    // makes use of md5 index, then filter possible hash collisions
    @Query("""
    SELECT *
    FROM application_client_authorizations
    WHERE state = :token
    OR (md5(authorization_code_value) = md5(:token) AND authorization_code_value = :token)
    OR (md5(access_token_value) = md5(:token) AND access_token_value = :token)
    OR (md5(refresh_token_value) = md5(:token) AND refresh_token_value = :token)
    LIMIT 1
    """)
    Optional<ApplicationClientAuthorizationEntity> findByAnyToken(@Param("token") String token);

    @Query("""
    SELECT
        auth.*,
        COALESCE(ARRAY_AGG(auth_acc.gw2_account_id) FILTER ( WHERE auth_acc.gw2_account_id IS NOT NULL ), ARRAY[]::UUID[]) AS gw2_account_ids
    FROM application_client_authorizations auth
    LEFT JOIN application_client_authorization_gw2_accounts auth_acc
    ON auth.id = auth_acc.application_client_authorization_id
    WHERE auth.account_id = :account_id
    AND auth.application_client_id = :application_client_id
    GROUP BY auth.id
    """)
    List<ApplicationClientAuthorizationWithGw2AccountIdsEntity> findAllWithGw2AccountIdsByAccountIdAndApplicationClientId(@Param("account_id") UUID accountId, @Param("application_client_id") UUID applicationClientId);

    @Query("""
    SELECT auth.id
    FROM (
        SELECT id, account_id
        FROM application_client_authorizations
        WHERE account_id = :account_id
        AND application_client_id = :application_client_id
        AND authorized_scopes @> ARRAY[ :authorized_scopes ]::TEXT[]
        ORDER BY creation_time DESC
        LIMIT 1
    ) auth
    LEFT JOIN application_client_authorization_gw2_accounts auth_gw2_acc
    ON auth.id = auth_gw2_acc.application_client_authorization_id
    LEFT JOIN gw2_account_api_tokens gw2_acc_tk
    ON auth_gw2_acc.account_id = gw2_acc_tk.account_id AND auth_gw2_acc.gw2_account_id = gw2_acc_tk.gw2_account_id
    LEFT JOIN gw2_account_verifications gw2_acc_ver
    ON auth_gw2_acc.account_id = gw2_acc_ver.account_id AND auth_gw2_acc.gw2_account_id = gw2_acc_ver.gw2_account_id
    GROUP BY auth.id
    HAVING BOOL_AND(gw2_acc_tk.last_valid_time = gw2_acc_tk.last_valid_check_time)
    AND (( NOT :requires_gw2_accs ) OR ( COUNT(DISTINCT auth_gw2_acc.gw2_account_id) > 0 ))
    AND (( NOT :verified_only ) OR ( COUNT(DISTINCT gw2_acc_ver.gw2_account_id) = COUNT(DISTINCT auth_gw2_acc.gw2_account_id) ))
    """)
    Optional<String> findLatestForNewAuthorization(@Param("account_id") UUID accountId,
                                                   @Param("application_client_id") UUID applicationClientId,
                                                   @Param("authorized_scopes") Set<String> scopes,
                                                   @Param("requires_gw2_accs") boolean requiresGw2Accs,
                                                   @Param("verified_only") boolean verifiedOnly);

    @Query("""
    SELECT
        auth.*,
        COALESCE(ARRAY_AGG(auth_acc.gw2_account_id) FILTER ( WHERE auth_acc.gw2_account_id IS NOT NULL ), ARRAY[]::UUID[]) AS gw2_account_ids
    FROM application_client_authorizations auth
    LEFT JOIN application_client_authorization_gw2_accounts auth_acc
    ON auth.id = auth_acc.application_client_authorization_id
    WHERE auth.id = :id
    AND auth.account_id = :account_id
    GROUP BY auth.id
    """)
    Optional<ApplicationClientAuthorizationWithGw2AccountIdsEntity> findWithGw2AccountIdsByIdAndAccountId(@Param("id") String id, @Param("account_id") UUID accountId);

    @Modifying
    @Query("DELETE FROM application_client_authorizations WHERE id = :id AND account_id = :account_id")
    boolean deleteByIdAndAccountId(@Param("id") String id, @Param("account_id") UUID accountId);

    @Modifying
    @Query("""
    DELETE FROM application_client_authorizations
    WHERE COALESCE(GREATEST(authorization_code_expires_at, access_token_expires_at, refresh_token_expires_at), (last_update_time + INTERVAL '1 DAY')) <= :now
    """)
    int deleteAllExpired(@Param("now") Instant now);
}
