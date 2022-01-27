package com.gw2auth.oauth2.server.web.client.consent;

import com.gw2auth.oauth2.server.repository.client.consent.ClientConsentLogEntity;
import com.gw2auth.oauth2.server.repository.client.consent.ClientConsentLogRepository;
import com.gw2auth.oauth2.server.service.client.consent.ClientConsent;
import com.gw2auth.oauth2.server.service.client.consent.ClientConsentService;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistration;
import com.gw2auth.oauth2.server.service.client.registration.ClientRegistrationService;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUser;
import com.gw2auth.oauth2.server.web.AbstractRestController;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@RestController
public class ClientConsentController extends AbstractRestController {

    private static final int LOGS_PAGE_SIZE = 5;

    private final ClientConsentService clientConsentService;
    private final ClientRegistrationService clientRegistrationService;
    private final ClientConsentLogRepository clientConsentLogRepository;

    @Autowired
    public ClientConsentController(ClientConsentService clientConsentService,
                                   ClientRegistrationService clientRegistrationService,
                                   ClientConsentLogRepository clientConsentLogRepository) {

        this.clientConsentService = clientConsentService;
        this.clientRegistrationService = clientRegistrationService;
        this.clientConsentLogRepository = clientConsentLogRepository;
    }

    @GetMapping(value = "/api/client/consent", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<ClientConsentResponse> getClientConsents(@AuthenticationPrincipal Gw2AuthUser user) {
        final List<ClientConsent> clientConsents = this.clientConsentService.getClientConsents(user.getAccountId());

        // get all client registration ids for batch lookup
        final Set<Long> clientRegistrationIds = clientConsents.stream()
                .map(ClientConsent::clientRegistrationId)
                .collect(Collectors.toSet());

        final Map<Long, ClientRegistration> clientRegistrationById = this.clientRegistrationService.getClientRegistrations(clientRegistrationIds).stream()
                .collect(Collectors.toMap(ClientRegistration::id, Function.identity()));

        final List<ClientConsentResponse> result = new ArrayList<>(clientConsents.size());

        for (ClientConsent clientConsent : clientConsents) {
            final ClientRegistration clientRegistration = clientRegistrationById.get(clientConsent.clientRegistrationId());

            // only happens if theres a race, but dont want to add locks here
            if (clientRegistration != null) {
                result.add(ClientConsentResponse.create(clientConsent, clientRegistration));
            }
        }

        return result;
    }

    @GetMapping(value = "/api/client/consent/{clientId}/logs", produces = MediaType.APPLICATION_JSON_VALUE)
    public ClientAuthorizationLogsResponse getClientConsentLogPage(@AuthenticationPrincipal Gw2AuthUser user,
                                                                   @PathVariable("clientId") UUID clientId,
                                                                   @RequestParam(value = "page", required = false) Integer page) {

        if (page == null || page < 0) {
            page = 0;
        }

        final List<ClientAuthorizationLogsResponse.Log> logs;

        try (Stream<ClientConsentLogEntity> stream = this.clientConsentLogRepository.findByAccountIdAndClientId(user.getAccountId(), clientId, page, LOGS_PAGE_SIZE)) {
            logs = stream
                    .sorted(Comparator.comparing(ClientConsentLogEntity::timestamp).reversed())
                    .map(ClientAuthorizationLogsResponse.Log::create).collect(Collectors.toList());
        }

        final int nextPage;
        if (logs.size() >= LOGS_PAGE_SIZE) {
            nextPage = page + 1;
        } else {
            nextPage = -1;
        }

        return new ClientAuthorizationLogsResponse(page, nextPage, logs);
    }

    @DeleteMapping("/api/client/consent/{clientId}")
    public ResponseEntity<Void> deleteClientConsent(@AuthenticationPrincipal Gw2AuthUser user, @PathVariable("clientId") UUID clientId) {
        this.clientConsentService.deleteClientConsent(user.getAccountId(), clientId);
        return ResponseEntity.status(HttpStatus.OK).build();
    }
}
