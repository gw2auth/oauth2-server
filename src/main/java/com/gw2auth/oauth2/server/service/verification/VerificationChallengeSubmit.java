package com.gw2auth.oauth2.server.service.verification;

public record VerificationChallengeSubmit(VerificationChallengePending verificationChallengePending, boolean succeeded) {

}
