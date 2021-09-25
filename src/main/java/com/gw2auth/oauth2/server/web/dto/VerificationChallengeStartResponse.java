package com.gw2auth.oauth2.server.web.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.verification.VerificationChallengeStart;

public record VerificationChallengeStartResponse(@JsonProperty("challengeId") long challengeId, @JsonProperty("challengeName") String challengeName, @JsonProperty("message") String message) {

    public static VerificationChallengeStartResponse create(VerificationChallengeStart value) {
        return new VerificationChallengeStartResponse(value.challengeId(), value.challengeName(), value.message());
    }
}
