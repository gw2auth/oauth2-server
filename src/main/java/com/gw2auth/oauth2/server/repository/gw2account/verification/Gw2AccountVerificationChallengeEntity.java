package com.gw2auth.oauth2.server.repository.gw2account.verification;

import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Table("gw2_account_verification_challenges")
public record Gw2AccountVerificationChallengeEntity(@Column("account_id") UUID accountId,
                                                    @Column("gw2_account_id") String gw2AccountId,
                                                    @Column("challenge_id") long challengeId,
                                                    @Column("state") String state,
                                                    @Column("gw2_api_token") String gw2ApiToken,
                                                    @Column("started_at") Instant startedAt,
                                                    @Column("timeout_at") Instant timeoutAt) {

}
