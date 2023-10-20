package com.gw2auth.oauth2.server.repository.gw2account.verification;

import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Table("gw2_account_verification_challenges")
public record Gw2AccountVerificationChallengeEntity(@Column("account_id") UUID accountId,
                                                    @Column("challenge_id") long challengeId,
                                                    @Column("state") String state,
                                                    @Column("creation_time") Instant creationTime) {

}
