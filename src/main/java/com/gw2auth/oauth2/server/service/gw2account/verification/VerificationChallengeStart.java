package com.gw2auth.oauth2.server.service.gw2account.verification;

import java.time.Instant;
import java.util.Map;

public record VerificationChallengeStart(long challengeId, Map<String, Object> message, Instant nextAllowedStartTime) {

}
