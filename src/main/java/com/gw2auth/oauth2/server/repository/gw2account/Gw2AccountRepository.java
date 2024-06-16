package com.gw2auth.oauth2.server.repository.gw2account;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface Gw2AccountRepository extends BaseRepository<Gw2AccountEntity>, CustomGw2AccountRepository {

    @Override
    default Gw2AccountEntity save(Gw2AccountEntity entity) {
        return save(
                entity.accountId(),
                entity.gw2AccountId(),
                entity.gw2AccountName(),
                entity.lastNameCheckTime(),
                entity.creationTime(),
                entity.displayName(),
                entity.orderRank(),
                entity.displayName(),
                entity.orderRank()
        );
    }

    @Query("""
    INSERT INTO gw2_accounts
    (account_id, gw2_account_id, gw2_account_name, last_name_check_time, creation_time, display_name, order_rank)
    VALUES
    (:account_id, :gw2_account_id, :gw2_account_name, :last_name_check_time, :creation_time, :display_name, :order_rank)
    ON CONFLICT (account_id, gw2_account_id) DO UPDATE SET
    gw2_account_name = EXCLUDED.gw2_account_name,
    display_name = COALESCE(:display_name_if_exists, gw2_accounts.display_name),
    order_rank = COALESCE(:order_rank_if_exists, gw2_accounts.order_rank)
    RETURNING *
    """)
    Gw2AccountEntity save(@Param("account_id") UUID accountId,
                          @Param("gw2_account_id") UUID gw2AccountId,
                          @Param("gw2_account_name") String gw2AccountName,
                          @Param("last_name_check_time") Instant lastNameCheckTime,
                          @Param("creation_time") Instant creationTime,
                          @Param("display_name") String displayName,
                          @Param("order_rank") String orderRank,
                          @Param("display_name_if_exists") String displayNameIfExists,
                          @Param("order_rank_if_exists") String orderRankIfExists);

    @Query("""
    SELECT *
    FROM gw2_accounts
    WHERE account_id = :account_id
    AND gw2_account_id = :gw2_account_id
    """)
    Optional<Gw2AccountEntity> findByAccountIdAndGw2AccountId(@Param("account_id") UUID accountId, @Param("gw2_account_id") UUID gw2AccountId);

    @Query("""
    SELECT
        acc.account_id AS acc_account_id,
        acc.gw2_account_id AS acc_gw2_account_id,
        acc.gw2_account_name AS acc_gw2_account_name,
        acc.creation_time AS acc_creation_time,
        acc.display_name AS acc_display_name,
        acc.order_rank AS acc_order_rank,
        tk.account_id AS tk_account_id,
        tk.gw2_account_id AS tk_gw2_account_id,
        tk.creation_time AS tk_creation_time,
        tk.gw2_api_token AS tk_gw2_api_token,
        tk.gw2_api_permissions_bit_set AS tk_gw2_api_permissions_bit_set,
        tk.last_valid_time AS tk_last_valid_time,
        tk.last_valid_check_time AS tk_last_valid_check_time
    FROM gw2_accounts acc
    INNER JOIN gw2_account_api_tokens tk
    ON acc.account_id = tk.account_id AND acc.gw2_account_id = tk.gw2_account_id
    WHERE acc.account_id = :account_id
    """)
    List<Gw2AccountWithApiTokenEntity> findAllWithTokenByAccountId(@Param("account_id") UUID accountId);

    @Query("""
    SELECT
        acc.account_id AS acc_account_id,
        acc.gw2_account_id AS acc_gw2_account_id,
        acc.gw2_account_name AS acc_gw2_account_name,
        acc.creation_time AS acc_creation_time,
        acc.display_name AS acc_display_name,
        acc.order_rank AS acc_order_rank,
        tk.account_id AS tk_account_id,
        tk.gw2_account_id AS tk_gw2_account_id,
        tk.creation_time AS tk_creation_time,
        tk.gw2_api_token AS tk_gw2_api_token,
        tk.gw2_api_permissions_bit_set AS tk_gw2_api_permissions_bit_set,
        tk.last_valid_time AS tk_last_valid_time,
        tk.last_valid_check_time AS tk_last_valid_check_time
    FROM gw2_accounts acc
    LEFT JOIN gw2_account_api_tokens tk
    ON acc.account_id = tk.account_id AND acc.gw2_account_id = tk.gw2_account_id
    WHERE acc.account_id = :account_id
    AND acc.gw2_account_id = ANY(ARRAY[ :gw2_account_ids ]::UUID[])
    """)
    List<Gw2AccountWithOptionalApiTokenEntity> findAllWithOptionalTokenByAccountIdAndGw2AccountIds(@Param("account_id") UUID accountId, @Param("gw2_account_ids") Collection<UUID> gw2AccountIds);
}
