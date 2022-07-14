package com.gw2auth.oauth2.server.web.token;

import com.gw2auth.oauth2.server.service.apitoken.ApiToken;
import com.gw2auth.oauth2.server.service.apitoken.ApiTokenService;
import com.gw2auth.oauth2.server.service.client.authorization.ClientAuthorization;
import com.gw2auth.oauth2.server.service.client.authorization.ClientAuthorizationService;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistration;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistrationService;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUserV2;
import com.gw2auth.oauth2.server.service.verification.VerificationService;
import com.gw2auth.oauth2.server.web.AbstractRestController;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@RestController
public class ApiTokenController extends AbstractRestController {

    private final ApiTokenService apiTokenService;
    private final VerificationService verificationService;
    private final ClientAuthorizationService clientAuthorizationService;
    private final ClientRegistrationService clientRegistrationService;

    @Autowired
    public ApiTokenController(ApiTokenService apiTokenService, VerificationService verificationService, ClientAuthorizationService clientAuthorizationService, ClientRegistrationService clientRegistrationService) {
        this.apiTokenService = apiTokenService;
        this.verificationService = verificationService;
        this.clientAuthorizationService = clientAuthorizationService;
        this.clientRegistrationService = clientRegistrationService;
    }

    @GetMapping(value = "/api/token", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<ApiTokenResponse> getApiTokens(@AuthenticationPrincipal Gw2AuthUserV2 user) {
        final List<ApiToken> apiTokens = this.apiTokenService.getApiTokens(user.getAccountId());

        // get all gw2 account ids for authorization batch lookup
        final Set<UUID> gw2AccountIds = apiTokens.stream()
                .map(ApiToken::gw2AccountId)
                .collect(Collectors.toSet());

        // aggregate authorizations for later lookup
        final List<ClientAuthorization> clientAuthorizations = this.clientAuthorizationService.getClientAuthorizations(user.getAccountId(), gw2AccountIds);
        final Set<UUID> clientRegistrationIds = new HashSet<>(clientAuthorizations.size());
        final Map<UUID, Set<UUID>> clientRegistrationIdsByGw2AccountId = new HashMap<>(clientAuthorizations.size());

        for (ClientAuthorization clientAuthorization : clientAuthorizations) {
            clientRegistrationIds.add(clientAuthorization.clientRegistrationId());

            for (UUID gw2AccountId : clientAuthorization.gw2AccountIds()) {
                clientRegistrationIdsByGw2AccountId.computeIfAbsent(gw2AccountId, (k) -> new HashSet<>()).add(clientAuthorization.clientRegistrationId());
            }
        }

        // find all client registrations for the registration ids and remember them by id
        final Map<UUID, ClientRegistration> clientRegistrationById = this.clientRegistrationService.getClientRegistrations(clientRegistrationIds).stream()
                .collect(Collectors.toMap(ClientRegistration::id, Function.identity()));

        // find all verified gw2 account ids for this account (better than querying for every single one)
        final Set<UUID> verifiedGw2AccountIds = this.verificationService.getVerifiedGw2AccountIds(user.getAccountId());

        final List<ApiTokenResponse> response = new ArrayList<>(apiTokens.size());

        for (ApiToken apiToken : apiTokens) {
            final Set<UUID> clientRegistrationIdsForThisToken = clientRegistrationIdsByGw2AccountId.get(apiToken.gw2AccountId());
            final List<ApiTokenResponse.Authorization> authorizations;

            if (clientRegistrationIdsForThisToken != null && !clientRegistrationIdsForThisToken.isEmpty()) {
                authorizations = new ArrayList<>(clientRegistrationIdsForThisToken.size());

                for (UUID clientRegistrationId : clientRegistrationIdsForThisToken) {
                    final ClientRegistration clientRegistration = clientRegistrationById.get(clientRegistrationId);

                    if (clientRegistration != null) {
                        authorizations.add(ApiTokenResponse.Authorization.create(clientRegistration));
                    }
                }
            } else {
                authorizations = List.of();
            }

            response.add(ApiTokenResponse.create(apiToken, verifiedGw2AccountIds.contains(apiToken.gw2AccountId()), authorizations));
        }

        return response.stream()
                .sorted(Comparator.comparing(ApiTokenResponse::creationTime))
                .toList();
    }

    @PostMapping(value = "/api/token", produces = MediaType.APPLICATION_JSON_VALUE)
    public ApiTokenResponse addApiToken(@AuthenticationPrincipal Gw2AuthUserV2 user, @RequestBody String token) {
        final ApiToken apiToken = this.apiTokenService.addApiToken(user.getAccountId(), token);
        final boolean isVerified = Objects.equals(this.verificationService.getVerifiedAccountId(apiToken.gw2AccountId()).orElse(null), user.getAccountId());

        return ApiTokenResponse.create(apiToken, isVerified, List.of());
    }

    @PatchMapping(value = "/api/token/{gw2AccountId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ApiTokenResponse updateApiToken(@AuthenticationPrincipal Gw2AuthUserV2 user,
                                   @PathVariable("gw2AccountId") UUID gw2AccountId,
                                   @RequestParam(value = "displayName", required = false) String displayName,
                                   @RequestParam(value = "gw2ApiToken", required = false) String gw2ApiToken) {


        final ApiToken apiToken = this.apiTokenService.updateApiToken(user.getAccountId(), gw2AccountId, gw2ApiToken, displayName);

        final List<ClientAuthorization> clientAuthorizations = this.clientAuthorizationService.getClientAuthorizations(user.getAccountId(), Set.of(apiToken.gw2AccountId()));
        final List<ApiTokenResponse.Authorization> authorizations;

        if (!clientAuthorizations.isEmpty()) {
            final Set<UUID> clientRegistrationIds = clientAuthorizations.stream().map(ClientAuthorization::clientRegistrationId).collect(Collectors.toSet());

            authorizations = this.clientRegistrationService.getClientRegistrations(clientRegistrationIds).stream()
                    .map(ApiTokenResponse.Authorization::create)
                    .collect(Collectors.toList());
        } else {
            authorizations = List.of();
        }

        final boolean isVerified = Objects.equals(this.verificationService.getVerifiedAccountId(apiToken.gw2AccountId()).orElse(null), user.getAccountId());

        return ApiTokenResponse.create(apiToken, isVerified, authorizations);
    }

    @DeleteMapping(value = "/api/token/{gw2AccountId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public void deleteApiToken(@AuthenticationPrincipal Gw2AuthUserV2 user, @PathVariable("gw2AccountId") UUID gw2AccountId) {
        this.apiTokenService.deleteApiToken(user.getAccountId(), gw2AccountId);
    }
}
