package com.gw2auth.oauth2.server.service.verification;

import java.time.Instant;

public record VerificationChallengePending(long challengeId, String gw2AccountId, Instant startedAt) {

}
