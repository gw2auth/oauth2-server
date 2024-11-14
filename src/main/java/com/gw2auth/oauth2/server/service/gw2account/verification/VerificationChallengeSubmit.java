package com.gw2auth.oauth2.server.service.gw2account.verification;

import org.jspecify.annotations.Nullable;

public record VerificationChallengeSubmit(@Nullable VerificationChallengePending verificationChallengePending, boolean succeeded) {

}
