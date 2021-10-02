package com.gw2auth.oauth2.server.web.client.registration;

import com.gw2auth.oauth2.server.web.AbstractRestController;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistrationService;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

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
                .collect(Collectors.toList());
    }

    @GetMapping(value = "/api/client/registration/{clientId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public Optional<ClientRegistrationPrivateResponse> getClientRegistration(@AuthenticationPrincipal Gw2AuthUser user, @PathVariable("clientId") String clientId) {
        return this.clientRegistrationService.getClientRegistration(user.getAccountId(), clientId).map(ClientRegistrationPrivateResponse::create);
    }

    @PostMapping(value = "/api/client/registration", produces = MediaType.APPLICATION_JSON_VALUE)
    public ClientRegistrationCreationResponse createClientRegistration(@AuthenticationPrincipal Gw2AuthUser user, @RequestBody ClientRegistrationCreationRequest clientRegistrationCreationRequest) {
        return ClientRegistrationCreationResponse.create(this.clientRegistrationService.createClientRegistration(
                user.getAccountId(),
                clientRegistrationCreationRequest.displayName(),
                clientRegistrationCreationRequest.authorizationGrantTypes(),
                clientRegistrationCreationRequest.redirectUri()
        ));
    }

    @DeleteMapping("/api/client/registration/{clientId}")
    public ResponseEntity<Void> deleteClientRegistration(@AuthenticationPrincipal Gw2AuthUser user, @PathVariable("clientId") String clientId) {
        this.clientRegistrationService.deleteClientRegistration(user.getAccountId(), clientId);
        return ResponseEntity.status(HttpStatus.OK).build();
    }
}
