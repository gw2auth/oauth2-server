package com.gw2auth.oauth2.server.web.client.consent;

import com.gw2auth.oauth2.server.service.client.consent.ClientConsent;
import com.gw2auth.oauth2.server.service.client.consent.ClientConsentService;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistration;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistrationService;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUserV2;
import com.gw2auth.oauth2.server.web.AbstractRestController;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@RestController
public class ClientConsentController extends AbstractRestController {

    private final ClientConsentService clientConsentService;
    private final ClientRegistrationService clientRegistrationService;

    @Autowired
    public ClientConsentController(ClientConsentService clientConsentService, ClientRegistrationService clientRegistrationService) {

        this.clientConsentService = clientConsentService;
        this.clientRegistrationService = clientRegistrationService;
    }

    @GetMapping(value = "/api/client/consent", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<ClientConsentResponse> getClientConsents(@AuthenticationPrincipal Gw2AuthUserV2 user) {
        final List<ClientConsent> clientConsents = this.clientConsentService.getClientConsents(user.getAccountId());

        // get all client registration ids for batch lookup
        final Set<UUID> clientRegistrationIds = clientConsents.stream()
                .map(ClientConsent::clientRegistrationId)
                .collect(Collectors.toSet());

        final Map<UUID, ClientRegistration> clientRegistrationById = this.clientRegistrationService.getClientRegistrations(clientRegistrationIds).stream()
                .collect(Collectors.toMap(ClientRegistration::id, Function.identity()));

        final List<ClientConsentResponse> result = new ArrayList<>(clientConsents.size());

        for (ClientConsent clientConsent : clientConsents) {
            final ClientRegistration clientRegistration = clientRegistrationById.get(clientConsent.clientRegistrationId());

            // only happens if theres a race, but dont want to add locks here
            if (clientRegistration != null) {
                result.add(ClientConsentResponse.create(clientConsent, clientRegistration));
            }
        }

        return result.stream()
                .sorted(Comparator.comparing((v) -> v.clientRegistration().displayName()))
                .toList();
    }

    @DeleteMapping("/api/client/consent/{clientId}")
    public ResponseEntity<Void> deleteClientConsent(@AuthenticationPrincipal Gw2AuthUserV2 user, @PathVariable("clientId") UUID clientId) {
        this.clientConsentService.deleteClientConsent(user.getAccountId(), clientId);
        return ResponseEntity.status(HttpStatus.OK).build();
    }
}
