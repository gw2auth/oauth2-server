package com.gw2auth.oauth2.server.repository.gw2account.verification;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.springframework.data.jdbc.repository.query.Modifying;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface Gw2AccountVerificationRepository extends BaseRepository<Gw2AccountVerificationEntity> {

    @Override
    default Gw2AccountVerificationEntity save(Gw2AccountVerificationEntity entity) {
        return save(entity.gw2AccountId(), entity.accountId());
    }

    @Query("""
    INSERT INTO gw2_account_verifications
    (gw2_account_id, account_id)
    VALUES
    (:gw2_account_id, :account_id)
    ON CONFLICT (gw2_account_id) DO UPDATE SET
    account_id = EXCLUDED.account_id
    RETURNING *
    """)
    Gw2AccountVerificationEntity save(@Param("gw2_account_id") UUID gw2AccountId, @Param("account_id") UUID accountId);

    @Query("SELECT * FROM gw2_account_verifications WHERE gw2_account_id = :gw2_account_id")
    Optional<Gw2AccountVerificationEntity> findByGw2AccountId(@Param("gw2_account_id") UUID gw2AccountId);

    @Query("SELECT * FROM gw2_account_verifications WHERE account_id = :account_id")
    List<Gw2AccountVerificationEntity> findAllByAccountId(@Param("account_id") UUID accountId);

    @Modifying
    @Query("DELETE FROM gw2_account_verifications WHERE gw2_account_id = :gw2_account_id")
    int deleteByGw2AccountId(@Param("gw2_account_id") UUID gw2AccountId);
}
