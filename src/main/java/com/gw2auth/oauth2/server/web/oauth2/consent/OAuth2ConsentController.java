package com.gw2auth.oauth2.server.web.oauth2.consent;

import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.apitoken.ApiToken;
import com.gw2auth.oauth2.server.service.apitoken.ApiTokenService;
import com.gw2auth.oauth2.server.service.client.authorization.ClientAuthorization;
import com.gw2auth.oauth2.server.service.client.authorization.ClientAuthorizationService;
import com.gw2auth.oauth2.server.service.client.consent.ClientConsentService;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistration;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistrationService;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUser;
import com.gw2auth.oauth2.server.service.verification.VerificationService;
import com.gw2auth.oauth2.server.util.Utils;
import com.gw2auth.oauth2.server.web.AbstractRestController;
import com.gw2auth.oauth2.server.web.client.consent.ClientRegistrationPublicResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
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

    private final ClientRegistrationService clientRegistrationService;
    private final ClientAuthorizationService clientAuthorizationService;
    private final OAuth2AuthorizationService auth2AuthorizationService;
    private final ApiTokenService apiTokenService;
    private final VerificationService verificationService;

    @Autowired
    public OAuth2ConsentController(ClientRegistrationService clientRegistrationService, ClientAuthorizationService clientAuthorizationService, OAuth2AuthorizationService auth2AuthorizationService, ApiTokenService apiTokenService, VerificationService verificationService) {
        this.clientRegistrationService = clientRegistrationService;
        this.clientAuthorizationService = clientAuthorizationService;
        this.auth2AuthorizationService = auth2AuthorizationService;
        this.apiTokenService = apiTokenService;
        this.verificationService = verificationService;
    }

    @GetMapping(value = "/api/oauth2/consent", produces = MediaType.APPLICATION_JSON_VALUE)
    public OAuth2ConsentInfoResponse oauth2ConsentInformation(@AuthenticationPrincipal Gw2AuthUser user,
                                                              @RequestParam(OAuth2ParameterNames.CLIENT_ID) UUID clientId,
                                                              @RequestParam(OAuth2ParameterNames.STATE) String state,
                                                              @RequestParam(OAuth2ParameterNames.SCOPE) String scopes) {

        final ClientRegistration clientRegistration = this.clientRegistrationService.getClientRegistration(clientId).orElseThrow();
        final Set<String> requestedScopes = Utils.split(scopes, " ").collect(Collectors.toSet());
        final Set<Gw2ApiPermission> requestedGw2ApiPermissions = requestedScopes.stream()
                .flatMap((scope) -> Gw2ApiPermission.fromOAuth2(scope).stream())
                .collect(Collectors.toSet());
        final boolean requestedVerifiedInformation = requestedScopes.contains(ClientConsentService.GW2AUTH_VERIFIED_SCOPE);

        final List<ApiToken> apiTokens = this.apiTokenService.getApiTokens(user.getAccountId()).stream()
                .sorted(Comparator.comparing(ApiToken::creationTime))
                .toList();

        final List<OAuth2ConsentInfoResponse.MinimalApiToken> apiTokensWithSufficientPermissionResponses = new ArrayList<>();
        final List<OAuth2ConsentInfoResponse.MinimalApiToken> apiTokensWithInsufficientPermissionResponses = new ArrayList<>();
        final Set<UUID> verifiedGw2AccountIds;
        if (apiTokens.isEmpty() || !requestedVerifiedInformation) {
            verifiedGw2AccountIds = Set.of();
        } else {
            verifiedGw2AccountIds = this.verificationService.getVerifiedGw2AccountIds(user.getAccountId());
        }

        for (ApiToken apiToken : apiTokens) {
            final OAuth2ConsentInfoResponse.MinimalApiToken resultApiToken = OAuth2ConsentInfoResponse.MinimalApiToken.create(apiToken, verifiedGw2AccountIds.contains(apiToken.gw2AccountId()));

            if (apiToken.gw2ApiPermissions().containsAll(requestedGw2ApiPermissions)) {
                apiTokensWithSufficientPermissionResponses.add(resultApiToken);
            } else {
                apiTokensWithInsufficientPermissionResponses.add(resultApiToken);
            }
        }

        final Set<UUID> previouslyConsentedGw2AccountIds = this.clientAuthorizationService.getLatestClientAuthorization(user.getAccountId(), clientRegistration.id(), requestedScopes)
                .map(ClientAuthorization::gw2AccountIds)
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
                ClientRegistrationPublicResponse.create(clientRegistration),
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
