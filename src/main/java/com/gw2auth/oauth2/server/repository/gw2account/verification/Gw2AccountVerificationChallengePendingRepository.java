package com.gw2auth.oauth2.server.repository.gw2account.verification;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.springframework.data.jdbc.repository.query.Modifying;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface Gw2AccountVerificationChallengePendingRepository extends BaseRepository<Gw2AccountVerificationChallengePendingEntity> {

    @Override
    default Gw2AccountVerificationChallengePendingEntity save(Gw2AccountVerificationChallengePendingEntity entity) {
        return save(
                entity.accountId(),
                entity.gw2AccountId(),
                entity.challengeId(),
                entity.state(),
                entity.gw2ApiToken(),
                entity.creationTime(),
                entity.submitTime(),
                entity.timeoutTime()
        );
    }

    @Query("""
    INSERT INTO gw2_account_verification_pending_challenges
    (account_id, gw2_account_id, challenge_id, state, gw2_api_token, creation_time, submit_time, timeout_time)
    VALUES
    (:account_id, :gw2_account_id, :challenge_id, :state, :gw2_api_token, :creation_time, :submit_time, :timeout_time)
    ON CONFLICT (account_id, gw2_account_id) DO UPDATE SET
    challenge_id = EXCLUDED.challenge_id,
    state = EXCLUDED.state,
    gw2_api_token = EXCLUDED.gw2_api_token,
    creation_time = EXCLUDED.creation_time,
    submit_time = EXCLUDED.submit_time,
    timeout_time = EXCLUDED.timeout_time
    RETURNING *
    """)
    Gw2AccountVerificationChallengePendingEntity save(@Param("account_id") UUID accountId,
                                                      @Param("gw2_account_id") UUID gw2AccountId,
                                                      @Param("challenge_id") long challengeId,
                                                      @Param("state") String state,
                                                      @Param("gw2_api_token") String gw2ApiToken,
                                                      @Param("creation_time") Instant creationTime,
                                                      @Param("submit_time") Instant submitTime,
                                                      @Param("timeout_time") Instant timeoutTime);

    @Query("SELECT * FROM gw2_account_verification_pending_challenges WHERE account_id = :account_id AND gw2_account_id = :gw2_account_id")
    Optional<Gw2AccountVerificationChallengePendingEntity> findByAccountIdAndGw2AccountId(@Param("account_id") UUID accountId, @Param("gw2_account_id") UUID gw2AccountId);

    @Query("SELECT * FROM gw2_account_verification_pending_challenges")
    List<Gw2AccountVerificationChallengePendingEntity> findAll();

    @Modifying
    @Query("DELETE FROM gw2_account_verification_pending_challenges WHERE account_id = :account_id AND gw2_account_id = :gw2_account_id")
    boolean deleteByAccountIdAndGw2AccountId(@Param("account_id") UUID accountId, @Param("gw2_account_id") UUID gw2AccountId);
}
