package com.gw2auth.oauth2.server.web.token;

import com.gw2auth.oauth2.server.service.apitoken.ApiToken;
import com.gw2auth.oauth2.server.service.apitoken.ApiTokenService;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUser;
import com.gw2auth.oauth2.server.service.verification.VerificationService;
import com.gw2auth.oauth2.server.web.AbstractRestController;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
public class ApiTokenController extends AbstractRestController {

    private final ApiTokenService apiTokenService;
    private final VerificationService verificationService;

    @Autowired
    public ApiTokenController(ApiTokenService apiTokenService, VerificationService verificationService) {
        this.apiTokenService = apiTokenService;
        this.verificationService = verificationService;
    }

    @GetMapping(value = "/api/token", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<ApiTokenResponse> getApiTokens(@AuthenticationPrincipal Gw2AuthUser user) {
        final Set<String> verifiedGw2AccountIds = this.verificationService.getVerifiedGw2AccountIds(user.getAccountId());

        return this.apiTokenService.getApiTokens(user.getAccountId()).stream()
                .map((v) -> ApiTokenResponse.create(v, verifiedGw2AccountIds.contains(v.gw2AccountId())))
                .collect(Collectors.toList());
    }

    @PostMapping(value = "/api/token", produces = MediaType.APPLICATION_JSON_VALUE)
    public ApiTokenResponse addApiToken(@AuthenticationPrincipal Gw2AuthUser user, @RequestBody String token) {
        // a newly added token cannot be verified (right?)
        return ApiTokenResponse.create(this.apiTokenService.addApiToken(user.getAccountId(), token), false);
    }

    @PatchMapping(value = "/api/token/{gw2AccountId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ApiTokenResponse updateApiToken(@AuthenticationPrincipal Gw2AuthUser user,
                                   @PathVariable("gw2AccountId") String gw2AccountId,
                                   @RequestParam(value = "displayName", required = false) String displayName,
                                   @RequestParam(value = "gw2ApiToken", required = false) String gw2ApiToken) {


        final ApiToken apiToken = this.apiTokenService.updateApiToken(user.getAccountId(), gw2AccountId, gw2ApiToken, displayName);
        final boolean isVerified = this.verificationService.getVerifiedAccountId(apiToken.gw2AccountId()).orElse(-1L) == user.getAccountId();

        return ApiTokenResponse.create(apiToken, isVerified);
    }

    @DeleteMapping(value = "/api/token/{gw2AccountId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public void deleteApiToken(@AuthenticationPrincipal Gw2AuthUser user, @PathVariable("gw2AccountId") String gw2AccountId) {
        this.apiTokenService.deleteApiToken(user.getAccountId(), gw2AccountId);
    }
}
