package com.gw2auth.oauth2.server.web.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public record VerificationChallengeBootstrapResponse(@JsonProperty("availableChallenges") List<VerificationChallengeResponse> availableChallenges,
                                                     @JsonProperty("startedChallenge") VerificationChallengeStartResponse startedChallenge,
                                                     @JsonProperty("pendingChallenges") List<VerificationChallengePendingResponse> pendingChallenges) {
}
