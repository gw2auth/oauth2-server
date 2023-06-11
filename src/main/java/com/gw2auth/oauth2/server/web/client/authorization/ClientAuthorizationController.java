package com.gw2auth.oauth2.server.web.client.authorization;

import com.gw2auth.oauth2.server.service.application.client.authorization.ApplicationClientAuthorization;
import com.gw2auth.oauth2.server.service.application.client.authorization.ApplicationClientAuthorizationService;
import com.gw2auth.oauth2.server.service.gw2account.Gw2AccountService;
import com.gw2auth.oauth2.server.service.gw2account.Gw2AccountWithApiToken;
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
    private final Gw2AccountService gw2AccountService;

    @Autowired
    public ClientAuthorizationController(ApplicationClientAuthorizationService applicationClientAuthorizationService, Gw2AccountService gw2AccountService) {
        this.applicationClientAuthorizationService = applicationClientAuthorizationService;
        this.gw2AccountService = gw2AccountService;
    }

    @GetMapping(value = "/api/client/authorization/{clientId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<ClientAuthorizationResponse> getClientAuthorizations(@AuthenticationPrincipal Gw2AuthUserV2 user, @PathVariable("clientId") UUID clientId) {
        final List<ApplicationClientAuthorization> authorizations = this.applicationClientAuthorizationService.getApplicationClientAuthorizations(user.getAccountId(), clientId);

        // get all gw2-account ids for batch lookup
        final Set<UUID> gw2AccountIds = authorizations.stream()
                .flatMap((v) -> v.gw2AccountIds().stream())
                .collect(Collectors.toUnmodifiableSet());

        final Map<UUID, Gw2AccountWithApiToken> accountsWithTokenByGw2AccountId = this.gw2AccountService.getWithApiTokens(user.getAccountId(), gw2AccountIds).stream()
                .collect(Collectors.toMap((v) -> v.account().gw2AccountId(), Function.identity()));

        final List<ClientAuthorizationResponse> result = new ArrayList<>(authorizations.size());

        for (ApplicationClientAuthorization authorization : authorizations) {
            final List<ClientAuthorizationResponse.Token> tokens = new ArrayList<>(authorization.gw2AccountIds().size());

            for (UUID gw2AccountId : authorization.gw2AccountIds()) {
                final Gw2AccountWithApiToken accountWithToken = accountsWithTokenByGw2AccountId.get(gw2AccountId);

                if (accountWithToken != null) {
                    tokens.add(new ClientAuthorizationResponse.Token(gw2AccountId, accountWithToken.account().displayName()));
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
