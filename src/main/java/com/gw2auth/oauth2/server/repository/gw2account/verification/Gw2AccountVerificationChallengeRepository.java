package com.gw2auth.oauth2.server.repository.gw2account.verification;

import com.gw2auth.oauth2.server.repository.BaseRepository;
import org.springframework.data.jdbc.repository.query.Modifying;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface Gw2AccountVerificationChallengeRepository extends BaseRepository<Gw2AccountVerificationChallengeEntity> {

    @Override
    default Gw2AccountVerificationChallengeEntity save(Gw2AccountVerificationChallengeEntity entity) {
        return save(
                entity.accountId(),
                entity.challengeId(),
                entity.state(),
                entity.creationTime()
        );
    }

    @Query("""
    INSERT INTO gw2_account_verification_challenges
    (account_id, challenge_id, state, creation_time)
    VALUES
    (:account_id, :challenge_id, :state, :creation_time)
    ON CONFLICT (account_id) DO UPDATE SET
    challenge_id = EXCLUDED.challenge_id,
    state = EXCLUDED.state,
    creation_time = EXCLUDED.creation_time
    RETURNING *
    """)
    Gw2AccountVerificationChallengeEntity save(@Param("account_id") UUID accountId,
                                               @Param("challenge_id") long challengeId,
                                               @Param("state") String state,
                                               @Param("creation_time") Instant creationTime);

    @Query("SELECT * FROM gw2_account_verification_challenges WHERE account_id = :account_id")
    Optional<Gw2AccountVerificationChallengeEntity> findByAccountId(@Param("account_id") UUID accountId);

    @Modifying
    @Query("DELETE FROM gw2_account_verification_challenges WHERE account_id = :account_id")
    boolean deleteByAccountId(@Param("account_id") UUID accountId);
}
