package com.gw2auth.oauth2.server.web.verification;

import com.gw2auth.oauth2.server.service.user.Gw2AuthUser;
import com.gw2auth.oauth2.server.service.verification.VerificationChallengeStart;
import com.gw2auth.oauth2.server.service.verification.VerificationService;
import com.gw2auth.oauth2.server.web.AbstractRestController;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;

@RestController
public class VerificationController extends AbstractRestController {

    private final VerificationService verificationService;

    @Autowired
    public VerificationController(VerificationService verificationService) {
        this.verificationService = verificationService;
    }

    @GetMapping(value = "/api/verification/bootstrap", produces = MediaType.APPLICATION_JSON_VALUE)
    public VerificationChallengeBootstrapResponse getBootstrap(@AuthenticationPrincipal Gw2AuthUser user) {
        return new VerificationChallengeBootstrapResponse(
                getAvailableChallenges(),
                getStartedChallenge(user).getBody(),
                getPendingChallenges(user)
        );
    }

    @GetMapping(value = "/api/verification/challenge", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<VerificationChallengeResponse> getAvailableChallenges() {
        return this.verificationService.getAvailableChallenges().stream()
                .map(VerificationChallengeResponse::create)
                .sorted(Comparator.comparingLong(VerificationChallengeResponse::id))
                .toList();
    }

    @GetMapping(value = "/api/verification", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<VerificationChallengeStartResponse> getStartedChallenge(@AuthenticationPrincipal Gw2AuthUser user) {
        final Optional<VerificationChallengeStart> optional = this.verificationService.getStartedChallenge(user.getAccountId());
        if (optional.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        return ResponseEntity.ok(VerificationChallengeStartResponse.create(optional.get()));
    }

    @GetMapping(value = "/api/verification/pending", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<VerificationChallengePendingResponse> getPendingChallenges(@AuthenticationPrincipal Gw2AuthUser user) {
        return this.verificationService.getPendingChallenges(user.getAccountId()).stream()
                .map(VerificationChallengePendingResponse::create)
                .sorted(Comparator.comparing(VerificationChallengePendingResponse::startedAt))
                .toList();
    }

    @PostMapping(value = "/api/verification", produces = MediaType.APPLICATION_JSON_VALUE)
    public VerificationChallengeStartResponse startNewChallenge(@AuthenticationPrincipal Gw2AuthUser user, @RequestParam("challengeId") long challengeId) {
        return VerificationChallengeStartResponse.create(this.verificationService.startChallenge(user.getAccountId(), challengeId));
    }

    @PostMapping(value = "/api/verification/pending", produces = MediaType.APPLICATION_JSON_VALUE)
    public VerificationChallengeSubmitResponse submitChallenge(@AuthenticationPrincipal Gw2AuthUser user, @RequestParam("token") String gw2ApiToken) {
        return VerificationChallengeSubmitResponse.create(this.verificationService.submitChallenge(user.getAccountId(), gw2ApiToken));
    }
}
