package com.gw2auth.oauth2.server.service.verification;

import java.time.Instant;
import java.util.UUID;

public record VerificationChallengePending(long challengeId, UUID gw2AccountId, Instant startedAt) {

}
