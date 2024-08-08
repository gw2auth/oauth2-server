package com.gw2auth.oauth2.server.repository.gw2account.apitoken;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.springframework.data.jdbc.repository.query.Modifying;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.*;

@Repository
public interface Gw2AccountApiTokenRepository extends BaseRepository<Gw2AccountApiTokenEntity>, CustomGw2AccountApiTokenRepository {

    @Override
    default Gw2AccountApiTokenEntity save(Gw2AccountApiTokenEntity entity) {
        return save(
                entity.accountId(),
                entity.gw2AccountId(),
                entity.creationTime(),
                entity.gw2ApiToken(),
                entity.gw2ApiPermissionsBitSet(),
                entity.lastValidTime(),
                entity.lastValidCheckTime()
        );
    }

    @Query("""
    INSERT INTO gw2_account_api_tokens
    (account_id, gw2_account_id, creation_time, gw2_api_token, gw2_api_permissions_bit_set, last_valid_time, last_valid_check_time)
    VALUES
    (:account_id, :gw2_account_id, :creation_time, :gw2_api_token, :gw2_api_permissions_bit_set, :last_valid_time, :last_valid_check_time)
    ON CONFLICT (account_id, gw2_account_id) DO UPDATE SET
    gw2_api_token = EXCLUDED.gw2_api_token,
    gw2_api_permissions_bit_set = EXCLUDED.gw2_api_permissions_bit_set,
    last_valid_time = EXCLUDED.last_valid_time,
    last_valid_check_time = EXCLUDED.last_valid_check_time
    RETURNING *
    """)
    Gw2AccountApiTokenEntity save(@Param("account_id") UUID accountId,
                                  @Param("gw2_account_id") UUID gw2AccountId,
                                  @Param("creation_time") Instant creationTime,
                                  @Param("gw2_api_token") String gw2ApiToken,
                                  @Param("gw2_api_permissions_bit_set") int gw2ApiPermissionsBitSet,
                                  @Param("last_valid_time") Instant lastValidTime,
                                  @Param("last_valid_check_time") Instant lastValidCheckTime);

    @Query("""
    SELECT *
    FROM gw2_account_api_tokens
    WHERE account_id = :account_id
    AND gw2_account_id = ANY(ARRAY[ :gw2_account_ids ]::UUID[])
    """)
    List<Gw2AccountApiTokenEntity> findAllByAccountIdAndGw2AccountIds(@Param("account_id") UUID accountId, @Param("gw2_account_ids") Collection<UUID> gw2AccountIds);

    @Query("""
    SELECT *
    FROM gw2_account_api_tokens
    WHERE account_id = :account_id
    AND gw2_account_id = :gw2_account_id
    """)
    Optional<Gw2AccountApiTokenEntity> findByAccountIdAndGw2AccountId(@Param("account_id") UUID accountId, @Param("gw2_account_id") UUID gw2AccountId);

    @Query("""
    SELECT tk.account_id, tk.gw2_account_id, acc.gw2_account_name, tk.gw2_api_token
    FROM gw2_account_api_tokens tk
    INNER JOIN gw2_accounts acc
    ON tk.account_id = acc.account_id AND tk.gw2_account_id = acc.gw2_account_id
    WHERE ( tk.last_valid_time >= :last_valid_time OR tk.last_valid_check_time = tk.last_valid_time )
    AND (tk.last_valid_check_time <= :last_valid_check_time OR acc.last_name_check_time <= :last_name_check_time)
    ORDER BY tk.last_valid_check_time
    LIMIT :limit
    """)
    List<Gw2AccountRefreshEntity> findAllApplicableForRefresh(
        @Param("last_valid_time") Instant lastValidTimeGTE,
        @Param("last_valid_check_time") Instant lastValidCheckTimeLTE,
        @Param("last_name_check_time") Instant lastNameCheckTimeLTE,
        @Param("limit") int limit
    );

    @Modifying
    @Query("""
    DELETE FROM gw2_account_api_tokens
    WHERE account_id = :account_id
    AND gw2_account_id = :gw2_account_id
    """)
    boolean deleteByAccountIdAndGw2AccountId(@Param("account_id") UUID accountId, @Param("gw2_account_id") UUID gw2AccountId);

    @Modifying
    @Query("""
    DELETE FROM gw2_account_api_tokens
    WHERE gw2_account_id = :gw2_account_id
    AND account_id <> :account_id
    """)
    void deleteAllByGw2AccountIdExceptForAccountId(@Param("gw2_account_id") UUID gw2AccountId, @Param("account_id") UUID accountId);
}
