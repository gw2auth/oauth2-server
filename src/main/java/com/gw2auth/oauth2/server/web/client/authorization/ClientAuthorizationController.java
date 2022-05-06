package com.gw2auth.oauth2.server.web.client.authorization;

import com.gw2auth.oauth2.server.service.apitoken.ApiToken;
import com.gw2auth.oauth2.server.service.apitoken.ApiTokenService;
import com.gw2auth.oauth2.server.service.client.authorization.ClientAuthorization;
import com.gw2auth.oauth2.server.service.client.authorization.ClientAuthorizationService;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUser;
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
public class ClientAuthorizationController extends AbstractRestController {

    private final ClientAuthorizationService clientAuthorizationService;
    private final ApiTokenService apiTokenService;

    @Autowired
    public ClientAuthorizationController(ClientAuthorizationService clientAuthorizationService, ApiTokenService apiTokenService) {
        this.clientAuthorizationService = clientAuthorizationService;
        this.apiTokenService = apiTokenService;
    }

    @GetMapping(value = "/api/client/authorization/{clientId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<ClientAuthorizationResponse> getClientAuthorizations(@AuthenticationPrincipal Gw2AuthUser user, @PathVariable("clientId") UUID clientId) {
        final List<ClientAuthorization> clientAuthorizations = this.clientAuthorizationService.getClientAuthorizations(user.getAccountId(), clientId);

        // get all gw2-account ids for batch lookup
        final Set<UUID> gw2AccountIds = clientAuthorizations.stream()
                .flatMap((v) -> v.gw2AccountIds().stream())
                .collect(Collectors.toSet());

        final Map<UUID, ApiToken> apiTokenByGw2AccountId = this.apiTokenService.getApiTokens(user.getAccountId(), gw2AccountIds).stream()
                .collect(Collectors.toMap(ApiToken::gw2AccountId, Function.identity()));

        final List<ClientAuthorizationResponse> result = new ArrayList<>(clientAuthorizations.size());

        for (ClientAuthorization clientAuthorization : clientAuthorizations) {
            final List<ClientAuthorizationResponse.Token> tokens = new ArrayList<>(clientAuthorization.gw2AccountIds().size());

            for (UUID gw2AccountId : clientAuthorization.gw2AccountIds()) {
                final ApiToken apiToken = apiTokenByGw2AccountId.get(gw2AccountId);

                if (apiToken != null) {
                    tokens.add(new ClientAuthorizationResponse.Token(gw2AccountId, apiToken.displayName()));
                }
            }

            result.add(ClientAuthorizationResponse.create(
                    clientAuthorization,
                    tokens.stream()
                            .sorted(Comparator.comparing(ClientAuthorizationResponse.Token::displayName))
                            .toList()
            ));
        }

        return result.stream()
                .sorted(Comparator.comparing(ClientAuthorizationResponse::creationTime))
                .toList();
    }

    @DeleteMapping(value = "/api/client/authorization/_/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Void> deleteClientAuthorization(@AuthenticationPrincipal Gw2AuthUser user,
                                                          @PathVariable("id") String id) {

        if (this.clientAuthorizationService.deleteClientAuthorization(user.getAccountId(), id)) {
            return ResponseEntity.status(HttpStatus.OK).build();
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
    }
}
