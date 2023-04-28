package com.gw2auth.oauth2.server.web.client.authorization;

import com.gw2auth.oauth2.server.service.application.client.authorization.ApplicationClientAuthorization;
import com.gw2auth.oauth2.server.service.application.client.authorization.ApplicationClientAuthorizationService;
import com.gw2auth.oauth2.server.service.gw2account.apitoken.Gw2AccountApiToken;
import com.gw2auth.oauth2.server.service.gw2account.apitoken.Gw2AccountApiTokenService;
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
public class ClientAuthorizationController extends AbstractRestController {

    private final ApplicationClientAuthorizationService applicationClientAuthorizationService;
    private final Gw2AccountApiTokenService gw2AccountApiTokenService;

    @Autowired
    public ClientAuthorizationController(ApplicationClientAuthorizationService applicationClientAuthorizationService,
                                         Gw2AccountApiTokenService gw2AccountApiTokenService) {
        this.applicationClientAuthorizationService = applicationClientAuthorizationService;
        this.gw2AccountApiTokenService = gw2AccountApiTokenService;
    }

    @GetMapping(value = "/api/client/authorization/{clientId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<ClientAuthorizationResponse> getClientAuthorizations(@AuthenticationPrincipal Gw2AuthUserV2 user, @PathVariable("clientId") UUID clientId) {
        final List<ApplicationClientAuthorization> authorizations = this.applicationClientAuthorizationService.getApplicationClientAuthorizations(user.getAccountId(), clientId);

        // get all gw2-account ids for batch lookup
        final Set<UUID> gw2AccountIds = authorizations.stream()
                .flatMap((v) -> v.gw2AccountIds().stream())
                .collect(Collectors.toSet());

        final Map<UUID, Gw2AccountApiToken> apiTokenByGw2AccountId = this.gw2AccountApiTokenService.getApiTokens(user.getAccountId(), gw2AccountIds).stream()
                .collect(Collectors.toMap(Gw2AccountApiToken::gw2AccountId, Function.identity()));

        final List<ClientAuthorizationResponse> result = new ArrayList<>(authorizations.size());

        for (ApplicationClientAuthorization authorization : authorizations) {
            final List<ClientAuthorizationResponse.Token> tokens = new ArrayList<>(authorization.gw2AccountIds().size());

            for (UUID gw2AccountId : authorization.gw2AccountIds()) {
                final Gw2AccountApiToken apiToken = apiTokenByGw2AccountId.get(gw2AccountId);

                if (apiToken != null) {
                    tokens.add(new ClientAuthorizationResponse.Token(gw2AccountId, apiToken.displayName()));
                }
            }

            result.add(ClientAuthorizationResponse.create(
                    authorization,
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
    public ResponseEntity<Void> deleteClientAuthorization(@AuthenticationPrincipal Gw2AuthUserV2 user, @PathVariable("id") String id) {
        this.applicationClientAuthorizationService.deleteApplicationClientAuthorization(user.getAccountId(), id);
        return ResponseEntity.status(HttpStatus.OK).build();
    }
}
