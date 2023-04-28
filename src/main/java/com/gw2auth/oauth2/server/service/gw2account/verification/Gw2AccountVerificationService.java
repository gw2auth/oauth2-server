package com.gw2auth.oauth2.server.service.gw2account.verification;

import java.util.*;

public interface Gw2AccountVerificationService {

    Set<UUID> getVerifiedGw2AccountIds(UUID accountId);
    Optional<UUID> getVerifiedAccountId(UUID gw2AccountId);
    List<VerificationChallenge<?>> getAvailableChallenges();
    Optional<VerificationChallengeStart> getStartedChallenge(UUID accountId);
    List<VerificationChallengePending> getPendingChallenges(UUID accountId);
    VerificationChallengeStart startChallenge(UUID accountId, long challengeId);
    VerificationChallengeSubmit submitChallenge(UUID accountId, String gw2ApiToken);
    void cancelPendingChallenge(UUID accountId, UUID gw2AccountId);
}
