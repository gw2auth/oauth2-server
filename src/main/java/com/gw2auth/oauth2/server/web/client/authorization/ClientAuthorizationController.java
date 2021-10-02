package com.gw2auth.oauth2.server.web.client.authorization;

import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationLogEntity;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationLogRepository;
import com.gw2auth.oauth2.server.service.apitoken.ApiToken;
import com.gw2auth.oauth2.server.service.apitoken.ApiTokenService;
import com.gw2auth.oauth2.server.service.client.authorization.ClientAuthorization;
import com.gw2auth.oauth2.server.service.client.authorization.ClientAuthorizationService;
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
public class ClientAuthorizationController extends AbstractRestController {

    private static final int LOGS_PAGE_SIZE = 5;

    private final ClientAuthorizationService clientAuthorizationService;
    private final ClientRegistrationService clientRegistrationService;
    private final ApiTokenService apiTokenService;
    private final ClientAuthorizationLogRepository clientAuthorizationLogRepository;

    @Autowired
    public ClientAuthorizationController(ClientAuthorizationService clientAuthorizationService, ClientRegistrationService clientRegistrationService, ApiTokenService apiTokenService, ClientAuthorizationLogRepository clientAuthorizationLogRepository) {
        this.clientAuthorizationService = clientAuthorizationService;
        this.clientRegistrationService = clientRegistrationService;
        this.apiTokenService = apiTokenService;
        this.clientAuthorizationLogRepository = clientAuthorizationLogRepository;
    }

    @GetMapping(value = "/api/client/authorization", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<ClientAuthorizationResponse> getClientRegistrations(@AuthenticationPrincipal Gw2AuthUser user) {
        final List<ClientAuthorization> clientAuthorizations = this.clientAuthorizationService.getClientAuthorizations(user.getAccountId());

        // get all client registration ids for batch lookup
        final Set<Long> clientRegistrationIds = clientAuthorizations.stream()
                .map(ClientAuthorization::clientRegistrationId)
                .collect(Collectors.toSet());

        // get all gw2-account ids for batch lookup
        final Set<String> gw2AccountIds = clientAuthorizations.stream()
                .flatMap((v) -> v.tokens().keySet().stream())
                .collect(Collectors.toSet());

        final Map<Long, ClientRegistration> clientRegistrationById = this.clientRegistrationService.getClientRegistrations(clientRegistrationIds).stream()
                .collect(Collectors.toMap(ClientRegistration::id, Function.identity()));

        final Map<String, ApiToken> apiTokenByGw2AccountId = this.apiTokenService.getApiTokens(user.getAccountId(), gw2AccountIds).stream()
                .collect(Collectors.toMap(ApiToken::gw2AccountId, Function.identity()));

        final List<ClientAuthorizationResponse> result = new ArrayList<>(clientAuthorizations.size());

        for (ClientAuthorization clientAuthorization : clientAuthorizations) {
            final ClientRegistration clientRegistration = clientRegistrationById.get(clientAuthorization.clientRegistrationId());

            // only happens if theres a race, but dont want to add locks here
            if (clientRegistration != null) {
                final List<ClientAuthorizationResponse.Token> tokens = new ArrayList<>(clientAuthorization.tokens().size());

                for (Map.Entry<String, ClientAuthorization.Token> entry : clientAuthorization.tokens().entrySet()) {
                    final ApiToken apiToken = apiTokenByGw2AccountId.get(entry.getKey());

                    if (apiToken != null) {
                        tokens.add(ClientAuthorizationResponse.Token.create(apiToken, entry.getValue()));
                    }
                }

                result.add(ClientAuthorizationResponse.create(clientAuthorization, clientRegistration, tokens));
            }
        }

        return result;
    }

    @GetMapping(value = "/api/client/authorization/{clientId}/logs", produces = MediaType.APPLICATION_JSON_VALUE)
    public ClientAuthorizationLogsResponse getClientAuthorizationLogPage(@AuthenticationPrincipal Gw2AuthUser user,
                                                                         @PathVariable("clientId") String clientId,
                                                                         @RequestParam(value = "page", required = false) Integer page) {

        if (page == null || page < 0) {
            page = 0;
        }

        final List<ClientAuthorizationLogsResponse.Log> logs;

        try (Stream<ClientAuthorizationLogEntity> stream = this.clientAuthorizationLogRepository.findByAccountIdAndClientId(user.getAccountId(), clientId, page, LOGS_PAGE_SIZE)) {
            logs = stream
                    .sorted(Comparator.comparing(ClientAuthorizationLogEntity::timestamp).reversed())
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

    @DeleteMapping("/api/client/authorization/{clientId}")
    public ResponseEntity<Void> deleteClientAuthorization(@AuthenticationPrincipal Gw2AuthUser user, @PathVariable("clientId") String clientId) {
        this.clientAuthorizationService.deleteClientAuthorization(user.getAccountId(), clientId);
        return ResponseEntity.status(HttpStatus.OK).build();
    }
}
