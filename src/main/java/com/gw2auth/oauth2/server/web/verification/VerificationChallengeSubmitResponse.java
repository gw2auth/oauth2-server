package com.gw2auth.oauth2.server.web.verification;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.gw2account.verification.VerificationChallengeSubmit;
import org.jspecify.annotations.Nullable;

public record VerificationChallengeSubmitResponse(@JsonProperty("pending") @Nullable VerificationChallengePendingResponse pending,
                                                  @JsonProperty("isSuccess") boolean isSuccess) {

    public static VerificationChallengeSubmitResponse create(VerificationChallengeSubmit value) {
        if (value.succeeded()) {
            return new VerificationChallengeSubmitResponse(null, true);
        } else {
            return new VerificationChallengeSubmitResponse(VerificationChallengePendingResponse.create(value.verificationChallengePending()), false);
        }
    }
}
