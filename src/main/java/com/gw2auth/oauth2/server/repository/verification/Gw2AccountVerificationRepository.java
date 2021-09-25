package com.gw2auth.oauth2.server.repository.verification;

import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface Gw2AccountVerificationRepository extends CrudRepository<Gw2AccountVerificationEntity, String> {

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
    Gw2AccountVerificationEntity save(@Param("gw2_account_id") String gw2AccountId, @Param("account_id") long accountId);

    @Query("SELECT * FROM gw2_account_verifications WHERE account_id = :account_id")
    List<Gw2AccountVerificationEntity> findAllByAccountId(@Param("account_id") long accountId);
}
