package com.gw2auth.oauth2.server.web.verification;

import com.gw2auth.oauth2.server.service.gw2account.verification.Gw2AccountVerificationService;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUserV2;
import com.gw2auth.oauth2.server.web.AbstractRestController;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Comparator;
import java.util.List;
import java.util.UUID;

@RestController
public class VerificationController extends AbstractRestController {

    private final Gw2AccountVerificationService gw2AccountVerificationService;

    @Autowired
    public VerificationController(Gw2AccountVerificationService gw2AccountVerificationService) {
        this.gw2AccountVerificationService = gw2AccountVerificationService;
    }

    @GetMapping(value = "/api/verification/bootstrap", produces = MediaType.APPLICATION_JSON_VALUE)
    public VerificationChallengeBootstrapResponse getBootstrap(@AuthenticationPrincipal Gw2AuthUserV2 user) {
        return new VerificationChallengeBootstrapResponse(
                getAvailableChallenges(),
                getStartedChallenge(user).getBody(),
                getPendingChallenges(user)
        );
    }

    @GetMapping(value = "/api/verification/challenge", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<VerificationChallengeResponse> getAvailableChallenges() {
        return this.gw2AccountVerificationService.getAvailableChallenges().stream()
                .map(VerificationChallengeResponse::create)
                .sorted(Comparator.comparingLong(VerificationChallengeResponse::id))
                .toList();
    }

    @GetMapping(value = "/api/verification", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<VerificationChallengeStartResponse> getStartedChallenge(@AuthenticationPrincipal Gw2AuthUserV2 user) {
        return this.gw2AccountVerificationService.getStartedChallenge(user.getAccountId())
                .map(VerificationChallengeStartResponse::create)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping(value = "/api/verification/pending", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<VerificationChallengePendingResponse> getPendingChallenges(@AuthenticationPrincipal Gw2AuthUserV2 user) {
        return this.gw2AccountVerificationService.getPendingChallenges(user.getAccountId()).stream()
                .map(VerificationChallengePendingResponse::create)
                .sorted(Comparator.comparing(VerificationChallengePendingResponse::startedAt))
                .toList();
    }

    @PostMapping(value = "/api/verification", produces = MediaType.APPLICATION_JSON_VALUE)
    public VerificationChallengeStartResponse startNewChallenge(@AuthenticationPrincipal Gw2AuthUserV2 user, @RequestParam("challengeId") long challengeId) {
        return VerificationChallengeStartResponse.create(this.gw2AccountVerificationService.startChallenge(user.getAccountId(), challengeId));
    }

    @PostMapping(value = "/api/verification/pending", produces = MediaType.APPLICATION_JSON_VALUE)
    public VerificationChallengeSubmitResponse submitChallenge(@AuthenticationPrincipal Gw2AuthUserV2 user, @RequestParam("token") String gw2ApiToken) {
        return VerificationChallengeSubmitResponse.create(this.gw2AccountVerificationService.submitChallenge(user.getAccountId(), gw2ApiToken));
    }

    @DeleteMapping(value = "/api/verification/pending/{gw2AccountId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Void> cancelPendingChallenge(@AuthenticationPrincipal Gw2AuthUserV2 user, @PathVariable("gw2AccountId") UUID gw2AccountId) {
        this.gw2AccountVerificationService.cancelPendingChallenge(user.getAccountId(), gw2AccountId);
        return ResponseEntity.ok(null);
    }
}
