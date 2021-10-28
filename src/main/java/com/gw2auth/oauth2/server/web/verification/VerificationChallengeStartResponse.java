package com.gw2auth.oauth2.server.web.verification;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.verification.VerificationChallengeStart;

import java.time.Instant;
import java.util.Map;

public record VerificationChallengeStartResponse(@JsonProperty("challengeId") long challengeId,
                                                 @JsonProperty("message") Map<String, Object> message,
                                                 @JsonProperty("nextAllowedStartTime") Instant nextAllowedStartTime) {

    public static VerificationChallengeStartResponse create(VerificationChallengeStart value) {
        return new VerificationChallengeStartResponse(value.challengeId(), value.message(), value.nextAllowedStartTime());
    }
}
