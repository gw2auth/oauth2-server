package com.gw2auth.oauth2.server.service.verification;

import java.util.*;

public interface VerificationService {

    Set<UUID> getVerifiedGw2AccountIds(long accountId);
    OptionalLong getVerifiedAccountId(UUID gw2AccountId);
    List<VerificationChallenge<?>> getAvailableChallenges();
    Optional<VerificationChallengeStart> getStartedChallenge(long accountId);
    List<VerificationChallengePending> getPendingChallenges(long accountId);
    VerificationChallengeStart startChallenge(long accountId, long challengeId);
    VerificationChallengeSubmit submitChallenge(long accountId, String gw2ApiToken);
}
