package com.gw2auth.oauth2.server.web.client.registration;

import com.gw2auth.oauth2.server.service.client.registration.ClientRegistrationService;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUser;
import com.gw2auth.oauth2.server.web.AbstractRestController;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Comparator;
import java.util.List;
import java.util.UUID;

@RestController
public class ClientRegistrationController extends AbstractRestController {

    private final ClientRegistrationService clientRegistrationService;

    @Autowired
    public ClientRegistrationController(ClientRegistrationService clientRegistrationService) {
        this.clientRegistrationService = clientRegistrationService;
    }

    @GetMapping(value = "/api/client/registration", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<ClientRegistrationPrivateResponse> getClientRegistrations(@AuthenticationPrincipal Gw2AuthUser user) {
        return this.clientRegistrationService.getClientRegistrations(user.getAccountId()).stream()
                .map(ClientRegistrationPrivateResponse::create)
                .sorted(Comparator.comparing(ClientRegistrationPrivateResponse::creationTime))
                .toList();
    }

    @GetMapping(value = "/api/client/registration/{clientId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> getClientRegistration(@AuthenticationPrincipal Gw2AuthUser user, @PathVariable("clientId") UUID clientId) {
        return fromOptional(this.clientRegistrationService.getClientRegistration(user.getAccountId(), clientId).map(ClientRegistrationPrivateResponse::create));
    }

    @PostMapping(value = "/api/client/registration", produces = MediaType.APPLICATION_JSON_VALUE)
    public ClientRegistrationCreationResponse createClientRegistration(@AuthenticationPrincipal Gw2AuthUser user, @RequestBody ClientRegistrationCreationRequest clientRegistrationCreationRequest) {
        return ClientRegistrationCreationResponse.create(this.clientRegistrationService.createClientRegistration(
                user.getAccountId(),
                clientRegistrationCreationRequest.displayName(),
                clientRegistrationCreationRequest.authorizationGrantTypes(),
                clientRegistrationCreationRequest.redirectUris()
        ));
    }

    @PutMapping(value = "/api/client/registration/{clientId}/redirect-uris", produces = MediaType.APPLICATION_JSON_VALUE)
    public ClientRegistrationPrivateResponse addRedirectUri(@AuthenticationPrincipal Gw2AuthUser user, @PathVariable("clientId") UUID clientId, @RequestBody String redirectUri) {
        return ClientRegistrationPrivateResponse.create(this.clientRegistrationService.addRedirectUri(
                user.getAccountId(),
                clientId,
                redirectUri
        ));
    }

    @DeleteMapping(value = "/api/client/registration/{clientId}/redirect-uris", produces = MediaType.APPLICATION_JSON_VALUE)
    public ClientRegistrationPrivateResponse removeRedirectUri(@AuthenticationPrincipal Gw2AuthUser user, @PathVariable("clientId") UUID clientId, @RequestParam("redirectUri") String redirectUri) {
        return ClientRegistrationPrivateResponse.create(this.clientRegistrationService.removeRedirectUri(
                user.getAccountId(),
                clientId,
                redirectUri
        ));
    }

    @PatchMapping(value = "/api/client/registration/{clientId}/client-secret", produces = MediaType.APPLICATION_JSON_VALUE)
    public ClientRegistrationCreationResponse regenerateClientSecret(@AuthenticationPrincipal Gw2AuthUser user, @PathVariable("clientId") UUID clientId) {
        return ClientRegistrationCreationResponse.create(this.clientRegistrationService.regenerateClientSecret(
                user.getAccountId(),
                clientId
        ));
    }

    @DeleteMapping("/api/client/registration/{clientId}")
    public ResponseEntity<Void> deleteClientRegistration(@AuthenticationPrincipal Gw2AuthUser user, @PathVariable("clientId") UUID clientId) {
        this.clientRegistrationService.deleteClientRegistration(user.getAccountId(), clientId);
        return ResponseEntity.status(HttpStatus.OK).build();
    }
}
