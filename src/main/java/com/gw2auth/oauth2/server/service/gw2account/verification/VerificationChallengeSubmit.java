package com.gw2auth.oauth2.server.service.gw2account.verification;

public record VerificationChallengeSubmit(VerificationChallengePending verificationChallengePending, boolean succeeded) {

}
