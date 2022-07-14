package com.gw2auth.oauth2.server.repository.verification;

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
public interface Gw2AccountVerificationChallengeRepository extends BaseRepository<Gw2AccountVerificationChallengeEntity> {

    @Override
    default Gw2AccountVerificationChallengeEntity save(Gw2AccountVerificationChallengeEntity entity) {
        return save(entity.accountId(), entity.gw2AccountId(), entity.challengeId(), entity.state(), entity.gw2ApiToken(), entity.startedAt(), entity.timeoutAt());
    }

    @Query("""
    INSERT INTO gw2_account_verification_challenges
    (account_id, gw2_account_id, challenge_id, state, gw2_api_token, started_at, timeout_at)
    VALUES
    (:account_id, :gw2_account_id, :challenge_id, :state, :gw2_api_token, :started_at, :timeout_at)
    ON CONFLICT (account_id, gw2_account_id) DO UPDATE SET
    challenge_id = EXCLUDED.challenge_id,
    state = EXCLUDED.state,
    gw2_api_token = EXCLUDED.gw2_api_token,
    started_at = EXCLUDED.started_at,
    timeout_at = EXCLUDED.timeout_at
    RETURNING *
    """)
    Gw2AccountVerificationChallengeEntity save(@Param("account_id") UUID accountId,
                                               @Param("gw2_account_id") String gw2AccountId,
                                               @Param("challenge_id") long challengeId,
                                               @Param("state") String state,
                                               @Param("gw2_api_token") String gw2ApiToken,
                                               @Param("started_at") Instant startedAt,
                                               @Param("timeout_at") Instant timeoutAt);

    @Query("SELECT * FROM gw2_account_verification_challenges WHERE account_id = :account_id")
    List<Gw2AccountVerificationChallengeEntity> findAllByAccountId(@Param("account_id") UUID accountId);

    @Query("SELECT * FROM gw2_account_verification_challenges WHERE account_id = :account_id AND gw2_account_id = :gw2_account_id")
    Optional<Gw2AccountVerificationChallengeEntity> findByAccountIdAndGw2AccountId(@Param("account_id") UUID accountId, @Param("gw2_account_id") String gw2AccountId);

    @Query("SELECT * FROM gw2_account_verification_challenges WHERE gw2_account_id <> ''")
    List<Gw2AccountVerificationChallengeEntity> findAllPending();

    @Modifying
    @Query("DELETE FROM gw2_account_verification_challenges WHERE account_id = :account_id AND gw2_account_id = :gw2_account_id")
    void deleteByAccountIdAndGw2AccountId(@Param("account_id") UUID accountId, @Param("gw2_account_id") String gw2AccountId);
}
