package com.gw2auth.oauth2.server.web.token;

import com.gw2auth.oauth2.server.service.Gw2AuthServiceException;
import com.gw2auth.oauth2.server.service.application.client.ApplicationClient;
import com.gw2auth.oauth2.server.service.application.client.ApplicationClientService;
import com.gw2auth.oauth2.server.service.application.client.authorization.ApplicationClientAuthorization;
import com.gw2auth.oauth2.server.service.application.client.authorization.ApplicationClientAuthorizationService;
import com.gw2auth.oauth2.server.service.gw2account.Gw2Account;
import com.gw2auth.oauth2.server.service.gw2account.Gw2AccountService;
import com.gw2auth.oauth2.server.service.gw2account.Gw2AccountWithApiToken;
import com.gw2auth.oauth2.server.service.gw2account.apitoken.Gw2AccountApiToken;
import com.gw2auth.oauth2.server.service.gw2account.apitoken.Gw2AccountApiTokenService;
import com.gw2auth.oauth2.server.service.gw2account.apitoken.Gw2AccountApiTokenServiceException;
import com.gw2auth.oauth2.server.service.gw2account.verification.Gw2AccountVerificationService;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUserV2;
import com.gw2auth.oauth2.server.web.AbstractRestController;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@RestController
public class ApiTokenController extends AbstractRestController {

    private final Gw2AccountService gw2AccountService;
    private final Gw2AccountApiTokenService gw2AccountApiTokenService;
    private final Gw2AccountVerificationService gw2AccountVerificationService;
    private final ApplicationClientService applicationClientService;
    private final ApplicationClientAuthorizationService applicationClientAuthorizationService;

    @Autowired
    public ApiTokenController(Gw2AccountService gw2AccountService,
                              Gw2AccountApiTokenService gw2AccountApiTokenService,
                              Gw2AccountVerificationService gw2AccountVerificationService,
                              ApplicationClientService applicationClientService,
                              ApplicationClientAuthorizationService applicationClientAuthorizationService) {
        this.gw2AccountService = gw2AccountService;
        this.gw2AccountApiTokenService = gw2AccountApiTokenService;
        this.gw2AccountVerificationService = gw2AccountVerificationService;
        this.applicationClientService = applicationClientService;
        this.applicationClientAuthorizationService = applicationClientAuthorizationService;
    }

    @GetMapping(value = "/api/token", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<ApiTokenResponse> getApiTokens(@AuthenticationPrincipal Gw2AuthUserV2 user) {
        final List<Gw2AccountWithApiToken> gw2AccountWithApiTokens  = this.gw2AccountService.getWithApiTokens(user.getAccountId());

        // get all gw2 account ids for authorization batch lookup
        final Set<UUID> gw2AccountIds = gw2AccountWithApiTokens.stream()
                .map((v) -> v.account().gw2AccountId())
                .collect(Collectors.toUnmodifiableSet());

        // aggregate authorizations for later lookup
        final List<ApplicationClientAuthorization> applicationClientAuthorizations = this.applicationClientAuthorizationService.getApplicationClientAuthorizations(user.getAccountId(), gw2AccountIds);
        final Set<UUID> applicationClientIds = new HashSet<>(applicationClientAuthorizations.size());
        final Map<UUID, Set<UUID>> applicationClientIdsByGw2AccountId = new HashMap<>(applicationClientAuthorizations.size());

        for (ApplicationClientAuthorization applicationClientAuthorization : applicationClientAuthorizations) {
            applicationClientIds.add(applicationClientAuthorization.applicationClientId());

            for (UUID gw2AccountId : applicationClientAuthorization.gw2AccountIds()) {
                applicationClientIdsByGw2AccountId.computeIfAbsent(gw2AccountId, (k) -> new HashSet<>()).add(applicationClientAuthorization.applicationClientId());
            }
        }

        // find all client registrations for the registration ids and remember them by id
        final Map<UUID, ApplicationClient> applicationClientById = this.applicationClientService.getApplicationClients(applicationClientIds).stream()
                .collect(Collectors.toMap(ApplicationClient::id, Function.identity()));

        // find all verified gw2 account ids for this account (better than querying for every single one)
        final Set<UUID> verifiedGw2AccountIds = this.gw2AccountVerificationService.getVerifiedGw2AccountIds(user.getAccountId());

        final List<ApiTokenResponse> response = new ArrayList<>(gw2AccountWithApiTokens.size());

        for (Gw2AccountWithApiToken gw2AccountWithApiToken : gw2AccountWithApiTokens) {
            final Gw2Account gw2Account = gw2AccountWithApiToken.account();
            final Gw2AccountApiToken apiToken = gw2AccountWithApiToken.apiToken();
            final Set<UUID> applicationClientIdsForThisToken = applicationClientIdsByGw2AccountId.get(gw2Account.gw2AccountId());
            final List<ApiTokenResponse.Authorization> authorizations;

            if (applicationClientIdsForThisToken != null && !applicationClientIdsForThisToken.isEmpty()) {
                authorizations = new ArrayList<>(applicationClientIdsForThisToken.size());

                for (UUID applicationClientId : applicationClientIdsForThisToken) {
                    final ApplicationClient applicationClient = applicationClientById.get(applicationClientId);

                    if (applicationClient != null) {
                        authorizations.add(ApiTokenResponse.Authorization.create(applicationClient));
                    }
                }
            } else {
                authorizations = List.of();
            }

            response.add(ApiTokenResponse.create(gw2Account, apiToken, verifiedGw2AccountIds.contains(gw2Account.gw2AccountId()), authorizations));
        }

        return response.stream()
                .sorted(Comparator.comparing(ApiTokenResponse::creationTime))
                .toList();
    }

    @PostMapping(value = "/api/token", produces = MediaType.APPLICATION_JSON_VALUE)
    public ApiTokenResponse addApiToken(@AuthenticationPrincipal Gw2AuthUserV2 user, @RequestBody String token) {
        final Gw2AccountApiToken apiToken = this.gw2AccountApiTokenService.addOrUpdateApiToken(user.getAccountId(), token);
        final Gw2Account gw2Account = this.gw2AccountService.getGw2Account(user.getAccountId(), apiToken.gw2AccountId()).orElseThrow();
        final boolean isVerified = Objects.equals(this.gw2AccountVerificationService.getVerifiedAccountId(apiToken.gw2AccountId()).orElse(null), user.getAccountId());

        return ApiTokenResponse.create(gw2Account, apiToken, isVerified, List.of());
    }

    @PatchMapping(value = "/api/token/{gw2AccountId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ApiTokenResponse updateApiToken(@AuthenticationPrincipal Gw2AuthUserV2 user,
                                                          @PathVariable("gw2AccountId") UUID gw2AccountId,
                                                          @RequestParam(value = "displayName", required = false) String displayName,
                                                          @RequestParam(value = "gw2ApiToken", required = false) String gw2ApiToken) {

        Gw2AccountWithApiToken gw2AccountWithApiToken = this.gw2AccountService.getWithApiToken(user.getAccountId(), gw2AccountId)
                .orElseThrow(() -> new Gw2AuthServiceException("The API Token does not yet exist", HttpStatus.NOT_FOUND));

        Gw2AccountApiToken gw2AccountApiToken = gw2AccountWithApiToken.apiToken();

        if (gw2ApiToken != null) {
            gw2AccountApiToken = this.gw2AccountApiTokenService.addOrUpdateApiToken(user.getAccountId(), gw2ApiToken);

            if (!gw2AccountApiToken.gw2AccountId().equals(gw2AccountId)) {
                throw new Gw2AccountApiTokenServiceException(Gw2AccountApiTokenServiceException.GW2_ACCOUNT_ID_MISMATCH, HttpStatus.BAD_REQUEST);
            }
        }

        if (displayName != null) {
            this.gw2AccountService.updateDisplayName(user.getAccountId(), gw2AccountApiToken.gw2AccountId(), displayName);
        } else {
            displayName = gw2AccountWithApiToken.account().displayName();
        }

        final List<ApplicationClientAuthorization> applicationClientAuthorizations = this.applicationClientAuthorizationService.getApplicationClientAuthorizations(user.getAccountId(), Set.of(gw2AccountApiToken.gw2AccountId()));
        final List<ApiTokenResponse.Authorization> authorizations;

        if (!applicationClientAuthorizations.isEmpty()) {
            final Set<UUID> clientRegistrationIds = applicationClientAuthorizations.stream()
                    .map(ApplicationClientAuthorization::applicationClientId)
                    .collect(Collectors.toUnmodifiableSet());

            authorizations = this.applicationClientService.getApplicationClients(clientRegistrationIds).stream()
                    .map(ApiTokenResponse.Authorization::create)
                    .collect(Collectors.toList());
        } else {
            authorizations = List.of();
        }

        final boolean isVerified = Objects.equals(this.gw2AccountVerificationService.getVerifiedAccountId(gw2AccountApiToken.gw2AccountId()).orElse(null), user.getAccountId());

        return ApiTokenResponse.create(gw2AccountApiToken, displayName, isVerified, authorizations);
    }

    @DeleteMapping(value = "/api/token/{gw2AccountId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public void deleteApiToken(@AuthenticationPrincipal Gw2AuthUserV2 user, @PathVariable("gw2AccountId") UUID gw2AccountId) {
        this.gw2AccountApiTokenService.deleteApiToken(user.getAccountId(), gw2AccountId);
    }
}
