package com.gw2auth.oauth2.server.service.verification;

public record VerificationChallengeStart(long challengeId, String challengeName, String message) {

}
