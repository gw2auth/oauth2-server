package com.gw2auth.oauth2.server.web.token;

import com.gw2auth.oauth2.server.service.apitoken.ApiToken;
import com.gw2auth.oauth2.server.service.apitoken.ApiTokenService;
import com.gw2auth.oauth2.server.service.client.authorization.ClientAuthorization;
import com.gw2auth.oauth2.server.service.client.authorization.ClientAuthorizationService;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistration;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistrationService;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUser;
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
    public List<ApiTokenResponse> getApiTokens(@AuthenticationPrincipal Gw2AuthUser user) {
        final List<ApiToken> apiTokens = this.apiTokenService.getApiTokens(user.getAccountId());

        // get all gw2 account ids for authorization batch lookup
        final Set<String> gw2AccountIds = apiTokens.stream()
                .map(ApiToken::gw2AccountId)
                .collect(Collectors.toSet());

        // aggregate authorizations for later lookup
        final List<ClientAuthorization> clientAuthorizations = this.clientAuthorizationService.getClientAuthorizations(user.getAccountId(), gw2AccountIds);
        final Set<Long> clientRegistrationIds = new HashSet<>(clientAuthorizations.size());
        final Map<String, List<ClientAuthorization>> clientAuthorizationsByGw2AccountId = new HashMap<>(clientAuthorizations.size());

        for (ClientAuthorization clientAuthorization : clientAuthorizations) {
            clientRegistrationIds.add(clientAuthorization.clientRegistrationId());

            for (String gw2AccountId : clientAuthorization.tokens().keySet()) {
                clientAuthorizationsByGw2AccountId.computeIfAbsent(gw2AccountId, (k) -> new ArrayList<>()).add(clientAuthorization);
            }
        }

        // find all client registrations for the registration ids and remember them by id
        final Map<Long, ClientRegistration> clientRegistrationById = this.clientRegistrationService.getClientRegistrations(clientRegistrationIds).stream()
                .collect(Collectors.toMap(ClientRegistration::id, Function.identity()));

        // find all verified gw2 account ids for this account (better than querying for every single one)
        final Set<String> verifiedGw2AccountIds = this.verificationService.getVerifiedGw2AccountIds(user.getAccountId());

        final List<ApiTokenResponse> response = new ArrayList<>(apiTokens.size());

        for (ApiToken apiToken : apiTokens) {
            final List<ClientAuthorization> authorizationsForThisToken = clientAuthorizationsByGw2AccountId.get(apiToken.gw2AccountId());
            final List<ApiTokenResponse.Authorization> authorizations;

            if (authorizationsForThisToken != null && !authorizationsForThisToken.isEmpty()) {
                authorizations = new ArrayList<>(authorizationsForThisToken.size());

                for (ClientAuthorization clientAuthorization : authorizationsForThisToken) {
                    final ClientRegistration clientRegistration = clientRegistrationById.get(clientAuthorization.clientRegistrationId());

                    if (clientRegistration != null) {
                        authorizations.add(ApiTokenResponse.Authorization.create(clientRegistration));
                    }
                }
            } else {
                authorizations = List.of();
            }

            response.add(ApiTokenResponse.create(apiToken, verifiedGw2AccountIds.contains(apiToken.gw2AccountId()), authorizations));
        }

        return response;
    }

    @PostMapping(value = "/api/token", produces = MediaType.APPLICATION_JSON_VALUE)
    public ApiTokenResponse addApiToken(@AuthenticationPrincipal Gw2AuthUser user, @RequestBody String token) {
        final ApiToken apiToken = this.apiTokenService.addApiToken(user.getAccountId(), token);
        final boolean isVerified = this.verificationService.getVerifiedAccountId(apiToken.gw2AccountId()).orElse(-1L) == user.getAccountId();

        return ApiTokenResponse.create(apiToken, isVerified, List.of());
    }

    @PatchMapping(value = "/api/token/{gw2AccountId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ApiTokenResponse updateApiToken(@AuthenticationPrincipal Gw2AuthUser user,
                                   @PathVariable("gw2AccountId") String gw2AccountId,
                                   @RequestParam(value = "displayName", required = false) String displayName,
                                   @RequestParam(value = "gw2ApiToken", required = false) String gw2ApiToken) {


        final ApiToken apiToken = this.apiTokenService.updateApiToken(user.getAccountId(), gw2AccountId, gw2ApiToken, displayName);

        final List<ClientAuthorization> clientAuthorizations = this.clientAuthorizationService.getClientAuthorizations(user.getAccountId(), Set.of(apiToken.gw2AccountId()));
        final List<ApiTokenResponse.Authorization> authorizations;

        if (!clientAuthorizations.isEmpty()) {
            final Set<Long> clientRegistrationIds = clientAuthorizations.stream().map(ClientAuthorization::clientRegistrationId).collect(Collectors.toSet());

            authorizations = this.clientRegistrationService.getClientRegistrations(clientRegistrationIds).stream()
                    .map(ApiTokenResponse.Authorization::create)
                    .collect(Collectors.toList());
        } else {
            authorizations = List.of();
        }

        final boolean isVerified = this.verificationService.getVerifiedAccountId(apiToken.gw2AccountId()).orElse(-1L) == user.getAccountId();

        return ApiTokenResponse.create(apiToken, isVerified, authorizations);
    }

    @DeleteMapping(value = "/api/token/{gw2AccountId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public void deleteApiToken(@AuthenticationPrincipal Gw2AuthUser user, @PathVariable("gw2AccountId") String gw2AccountId) {
        this.apiTokenService.deleteApiToken(user.getAccountId(), gw2AccountId);
    }
}
