package com.gw2auth.oauth2.server.web.verification;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.verification.VerificationChallengePending;

import java.time.Instant;
import java.util.UUID;

public record VerificationChallengePendingResponse(@JsonProperty("challengeId") long challengeId,
                                                   @JsonProperty("gw2AccountId") UUID gw2AccountId,
                                                   @JsonProperty("startedAt") Instant startedAt) {

    public static VerificationChallengePendingResponse create(VerificationChallengePending value) {
        return new VerificationChallengePendingResponse(value.challengeId(), value.gw2AccountId(), value.startedAt());
    }
}
