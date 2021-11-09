package com.gw2auth.oauth2.server.repository.apitoken;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.springframework.data.jdbc.repository.query.Modifying;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Repository
public interface ApiTokenRepository extends BaseRepository<ApiTokenEntity> {

    @Override
    default ApiTokenEntity save(ApiTokenEntity apiTokenEntity) {
        return save(apiTokenEntity.accountId(), apiTokenEntity.gw2AccountId(), apiTokenEntity.creationTime(), apiTokenEntity.gw2ApiToken(), apiTokenEntity.gw2ApiPermissions(), apiTokenEntity.displayName());
    }

    @Query("""
    INSERT INTO gw2_api_tokens
    (account_id, gw2_account_id, creation_time, gw2_api_token, gw2_api_permissions, display_name)
    VALUES
    (:account_id, :gw2_account_id, :creation_time, :gw2_api_token, ARRAY[ :gw2_api_permissions ]::VARCHAR[], :display_name)
    ON CONFLICT (account_id, gw2_account_id) DO UPDATE SET
    creation_time = EXCLUDED.creation_time,
    gw2_api_token = EXCLUDED.gw2_api_token,
    gw2_api_permissions = EXCLUDED.gw2_api_permissions,
    display_name = EXCLUDED.display_name
    RETURNING *
    """)
    ApiTokenEntity save(@Param("account_id") long accountId, @Param("gw2_account_id") String gw2AccountId, @Param("creation_time") Instant creationTime, @Param("gw2_api_token") String gw2ApiToken, @Param("gw2_api_permissions") Set<String> gw2ApiPermissions, @Param("display_name") String displayName);

    @Query("SELECT * FROM gw2_api_tokens WHERE account_id = :account_id")
    List<ApiTokenEntity> findAllByAccountId(@Param("account_id") long accountId);

    @Query("SELECT * FROM gw2_api_tokens WHERE account_id = :account_id AND gw2_account_id = ANY(ARRAY[ :gw2_account_ids ]::VARCHAR[])")
    List<ApiTokenEntity> findAllByAccountIdAndGw2AccountIds(@Param("account_id") long accountId, @Param("gw2_account_ids") Collection<String> gw2AccountIds);

    @Query("SELECT * FROM gw2_api_tokens WHERE account_id = :account_id AND gw2_account_id = :gw2_account_id")
    Optional<ApiTokenEntity> findByAccountIdAndGw2AccountId(@Param("account_id") long accountId, @Param("gw2_account_id") String gw2AccountId);

    @Modifying
    @Query("DELETE FROM gw2_api_tokens WHERE account_id = :account_id AND gw2_account_id = :gw2_account_id")
    int deleteByAccountIdAndGw2AccountId(@Param("account_id") long accountId, @Param("gw2_account_id") String gw2AccountId);

    @Modifying
    @Query("DELETE FROM gw2_api_tokens WHERE gw2_account_id = :gw2_account_id AND account_id <> :account_id")
    int deleteAllByGw2AccountIdExceptForAccountId(@Param("gw2_account_id") String gw2AccountId, @Param("account_id") long accountId);
}
