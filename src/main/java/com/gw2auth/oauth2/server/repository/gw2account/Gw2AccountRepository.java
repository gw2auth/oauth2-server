package com.gw2auth.oauth2.server.repository.gw2account;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.springframework.data.jdbc.repository.query.Modifying;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.UUID;

@Repository
public interface Gw2AccountRepository extends BaseRepository<Gw2AccountEntity> {

    @Override
    default Gw2AccountEntity save(Gw2AccountEntity entity) {
        return save(
                entity.accountId(),
                entity.gw2AccountId(),
                entity.creationTime(),
                entity.displayName(),
                entity.orderRank(),
                entity.displayName(),
                entity.orderRank()
        );
    }

    @Query("""
    INSERT INTO gw2_accounts
    (account_id, gw2_account_id, creation_time, display_name, order_rank)
    VALUES
    (:account_id, :gw2_account_id, :creation_time, :display_name, :order_rank)
    ON CONFLICT (account_id, gw2_account_id) DO UPDATE SET
    display_name = COALESCE(:display_name_if_exists, gw2_accounts.display_name),
    order_rank = COALESCE(:order_rank_if_exists, gw2_accounts.order_rank)
    RETURNING *
    """)
    Gw2AccountEntity save(@Param("account_id") UUID accountId,
                          @Param("gw2_account_id") UUID gw2AccountId,
                          @Param("creation_time") Instant creationTime,
                          @Param("display_name") String displayName,
                          @Param("order_rank") String orderRank,
                          @Param("display_name_if_exists") String displayNameIfExists,
                          @Param("order_rank_if_exists") String orderRankIfExists);

    @Modifying
    @Query("""
    UPDATE gw2_accounts
    SET display_name = :display_name
    WHERE account_id = :account_id
    AND gw2_account_id = :gw2_account_id
    """)
    void updateDisplayNameByAccountIdAndGw2AccountId(@Param("account_id") UUID accountId,
                                                     @Param("gw2_account_id") UUID gw2AccountId,
                                                     @Param("display_name") String displayName);

    @Modifying
    @Query("""
    UPDATE gw2_accounts
    SET order_rank = :order_rank
    WHERE account_id = :account_id
    AND gw2_account_id = :gw2_account_id
    """)
    void updateOrderRankByAccountIdAndGw2AccountId(@Param("account_id") UUID accountId,
                                                   @Param("gw2_account_id") UUID gw2AccountId,
                                                   @Param("order_rank") String orderRank);
}
