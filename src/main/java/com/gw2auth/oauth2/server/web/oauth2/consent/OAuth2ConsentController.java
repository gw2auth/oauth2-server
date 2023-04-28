package com.gw2auth.oauth2.server.web.oauth2.consent;

import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.application.client.ApplicationClient;
import com.gw2auth.oauth2.server.service.application.client.ApplicationClientService;
import com.gw2auth.oauth2.server.service.application.client.account.ApplicationClientAccountService;
import com.gw2auth.oauth2.server.service.application.client.authorization.ApplicationClientAuthorization;
import com.gw2auth.oauth2.server.service.application.client.authorization.ApplicationClientAuthorizationService;
import com.gw2auth.oauth2.server.service.gw2account.apitoken.Gw2AccountApiToken;
import com.gw2auth.oauth2.server.service.gw2account.apitoken.Gw2AccountApiTokenService;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUserV2;
import com.gw2auth.oauth2.server.service.gw2account.verification.Gw2AccountVerificationService;
import com.gw2auth.oauth2.server.util.Utils;
import com.gw2auth.oauth2.server.web.AbstractRestController;
import com.gw2auth.oauth2.server.web.client.consent.ClientRegistrationPublicResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

@RestController
public class OAuth2ConsentController extends AbstractRestController {

    private final Gw2AccountApiTokenService gw2AccountApiTokenService;
    private final ApplicationClientService applicationClientService;
    private final ApplicationClientAuthorizationService applicationClientAuthorizationService;
    private final OAuth2AuthorizationService auth2AuthorizationService;
    private final Gw2AccountVerificationService gw2AccountVerificationService;

    @Autowired
    public OAuth2ConsentController(Gw2AccountApiTokenService gw2AccountApiTokenService,
                                   ApplicationClientService applicationClientService,
                                   ApplicationClientAuthorizationService applicationClientAuthorizationService,
                                   OAuth2AuthorizationService auth2AuthorizationService,
                                   Gw2AccountVerificationService gw2AccountVerificationService) {
        this.gw2AccountApiTokenService = gw2AccountApiTokenService;
        this.applicationClientService = applicationClientService;
        this.applicationClientAuthorizationService = applicationClientAuthorizationService;
        this.auth2AuthorizationService = auth2AuthorizationService;
        this.gw2AccountVerificationService = gw2AccountVerificationService;
    }

    @GetMapping(value = "/api/oauth2/consent", produces = MediaType.APPLICATION_JSON_VALUE)
    public OAuth2ConsentInfoResponse oauth2ConsentInformation(@AuthenticationPrincipal Gw2AuthUserV2 user,
                                                              @RequestParam(OAuth2ParameterNames.CLIENT_ID) UUID clientId,
                                                              @RequestParam(OAuth2ParameterNames.STATE) String state,
                                                              @RequestParam(OAuth2ParameterNames.SCOPE) String scopes) {

        final ApplicationClient applicationClient = this.applicationClientService.getApplicationClients(Set.of(clientId)).stream().findAny().orElseThrow();
        final Set<String> requestedScopes = Utils.split(scopes, " ").collect(Collectors.toSet());
        final Set<Gw2ApiPermission> requestedGw2ApiPermissions = requestedScopes.stream()
                .flatMap((scope) -> Gw2ApiPermission.fromOAuth2(scope).stream())
                .collect(Collectors.toSet());
        final boolean requestedVerifiedInformation = requestedScopes.contains(ApplicationClientAccountService.GW2AUTH_VERIFIED_SCOPE);

        final List<Gw2AccountApiToken> gw2AccountApiTokens = this.gw2AccountApiTokenService.getApiTokens(user.getAccountId()).stream()
                .sorted(Comparator.comparing(Gw2AccountApiToken::creationTime))
                .toList();

        final List<OAuth2ConsentInfoResponse.MinimalApiToken> apiTokensWithSufficientPermissionResponses = new ArrayList<>();
        final List<OAuth2ConsentInfoResponse.MinimalApiToken> apiTokensWithInsufficientPermissionResponses = new ArrayList<>();
        final Set<UUID> verifiedGw2AccountIds;
        if (gw2AccountApiTokens.isEmpty() || !requestedVerifiedInformation) {
            verifiedGw2AccountIds = Set.of();
        } else {
            verifiedGw2AccountIds = this.gw2AccountVerificationService.getVerifiedGw2AccountIds(user.getAccountId());
        }

        for (Gw2AccountApiToken gw2AccountApiToken : gw2AccountApiTokens) {
            final OAuth2ConsentInfoResponse.MinimalApiToken resultApiToken = OAuth2ConsentInfoResponse.MinimalApiToken.create(gw2AccountApiToken, verifiedGw2AccountIds.contains(gw2AccountApiToken.gw2AccountId()));

            if (gw2AccountApiToken.gw2ApiPermissions().containsAll(requestedGw2ApiPermissions)) {
                apiTokensWithSufficientPermissionResponses.add(resultApiToken);
            } else {
                apiTokensWithInsufficientPermissionResponses.add(resultApiToken);
            }
        }

        final Set<UUID> previouslyConsentedGw2AccountIds = this.applicationClientAuthorizationService.getApplicationClientAuthorizations(user.getAccountId(), applicationClient.id()).stream()
                .filter((v) -> v.authorizedScopes().containsAll(requestedScopes))
                .sorted(Comparator.comparing(ApplicationClientAuthorization::creationTime).reversed())
                .map(ApplicationClientAuthorization::gw2AccountIds)
                .findFirst()
                .orElseGet(Set::of);

        final MultiValueMap<String, String> submitFormParameters = new LinkedMultiValueMap<>();
        submitFormParameters.set(OAuth2ParameterNames.CLIENT_ID, clientId.toString());
        submitFormParameters.set(OAuth2ParameterNames.STATE, state);

        requestedScopes.forEach((scope) -> submitFormParameters.add(OAuth2ParameterNames.SCOPE, scope));

        final String cancelUri = UriComponentsBuilder.fromPath("/api/oauth2/consent-deny")
                .replaceQueryParam(OAuth2ParameterNames.CLIENT_ID, clientId)
                .replaceQueryParam(OAuth2ParameterNames.STATE, state)
                .toUriString();

        return new OAuth2ConsentInfoResponse(
                ClientRegistrationPublicResponse.create(applicationClient),
                requestedGw2ApiPermissions,
                requestedVerifiedInformation,
                "/oauth2/authorize",
                submitFormParameters,
                cancelUri,
                apiTokensWithSufficientPermissionResponses,
                apiTokensWithInsufficientPermissionResponses,
                previouslyConsentedGw2AccountIds
        );
    }

    @GetMapping(value = "/api/oauth2/consent-deny")
    public ResponseEntity<Void> consentDeny(@RequestParam(OAuth2ParameterNames.STATE) String state) {
        final OAuth2Authorization oauth2Authorization = this.auth2AuthorizationService.findByToken(state, new OAuth2TokenType((OAuth2ParameterNames.STATE)));
        if (oauth2Authorization == null) {
            return ResponseEntity.badRequest().build();
        }

        final OAuth2AuthorizationRequest authorizationRequest = oauth2Authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
        if (authorizationRequest == null) {
            return ResponseEntity.badRequest().build();
        }

        final URI redirectUri = UriComponentsBuilder.fromHttpUrl(authorizationRequest.getRedirectUri())
                .replaceQueryParam(OAuth2ParameterNames.STATE, authorizationRequest.getState())
                .replaceQueryParam(OAuth2ParameterNames.ERROR, OAuth2ErrorCodes.ACCESS_DENIED)
                .replaceQueryParam(OAuth2ParameterNames.ERROR_DESCRIPTION, "The user has denied your application access.")
                .build()
                .toUri();

        return ResponseEntity.status(HttpStatus.FOUND).location(redirectUri).build();
    }
}
