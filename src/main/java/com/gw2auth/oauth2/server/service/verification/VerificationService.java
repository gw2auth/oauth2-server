package com.gw2auth.oauth2.server.service.verification;

import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;

public interface VerificationService {

    Set<String> getVerifiedGw2AccountIds(long accountId);
    OptionalLong getVerifiedAccountId(String gw2AccountId);
    List<VerificationChallenge<?>> getAvailableChallenges();
    Optional<VerificationChallengeStart> getStartedChallenge(long accountId);
    List<VerificationChallengePending> getPendingChallenges(long accountId);
    VerificationChallengeStart startChallenge(long accountId, long challengeId);
    VerificationChallengeSubmit submitChallenge(long accountId, String gw2ApiToken);
}
