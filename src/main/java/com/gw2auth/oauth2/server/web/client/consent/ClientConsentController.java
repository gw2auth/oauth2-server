package com.gw2auth.oauth2.server.web.client.consent;

import com.gw2auth.oauth2.server.service.application.account.ApplicationAccount;
import com.gw2auth.oauth2.server.service.application.account.ApplicationAccountService;
import com.gw2auth.oauth2.server.service.application.client.ApplicationClient;
import com.gw2auth.oauth2.server.service.application.client.ApplicationClientService;
import com.gw2auth.oauth2.server.service.application.client.account.ApplicationClientAccount;
import com.gw2auth.oauth2.server.service.application.client.account.ApplicationClientAccountService;
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

    private final ApplicationAccountService applicationAccountService;
    private final ApplicationClientService applicationClientService;
    private final ApplicationClientAccountService applicationClientAccountService;

    @Autowired
    public ClientConsentController(ApplicationAccountService applicationAccountService,
                                   ApplicationClientService applicationClientService,
                                   ApplicationClientAccountService applicationClientAccountService) {
        this.applicationAccountService = applicationAccountService;
        this.applicationClientService = applicationClientService;
        this.applicationClientAccountService = applicationClientAccountService;
    }

    @GetMapping(value = "/api/client/consent", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<ClientConsentResponse> getClientConsents(@AuthenticationPrincipal Gw2AuthUserV2 user) {
        final UUID accountId = user.getAccountId();
        final List<ApplicationClientAccount> applicationClientAccounts = this.applicationClientAccountService.getApplicationClientAccounts(accountId);
        final Set<UUID> applicationIds = new HashSet<>();
        final Set<UUID> applicationClientIds = new HashSet<>();

        for (ApplicationClientAccount applicationClientAccount : applicationClientAccounts) {
            applicationIds.add(applicationClientAccount.applicationId());
            applicationClientIds.add(applicationClientAccount.applicationClientId());
        }

        final Map<UUID, ApplicationAccount> applicationAccountByApplicationId = applicationIds.stream()
                .flatMap((v) -> this.applicationAccountService.getApplicationAccount(accountId, v).stream())
                .collect(Collectors.toMap(ApplicationAccount::applicationId, Function.identity()));

        final Map<UUID, ApplicationClient> applicationClientById = this.applicationClientService.getApplicationClients(applicationClientIds).stream()
                .collect(Collectors.toMap(ApplicationClient::id, Function.identity()));

        final List<ClientConsentResponse> result = new ArrayList<>(applicationClientAccounts.size());

        for (ApplicationClientAccount applicationClientAccount : applicationClientAccounts) {
            final ApplicationAccount applicationAccount = applicationAccountByApplicationId.get(applicationClientAccount.applicationId());
            final ApplicationClient applicationClient = applicationClientById.get(applicationClientAccount.applicationClientId());

            // only happens if theres a race, but dont want to add locks here
            if (applicationAccount != null && applicationClient != null) {
                result.add(ClientConsentResponse.create(applicationClientAccount, applicationAccount, applicationClient));
            }
        }

        return result.stream()
                .sorted(Comparator.comparing((v) -> v.clientRegistration().displayName()))
                .toList();
    }

    @DeleteMapping("/api/client/consent/{clientId}")
    public ResponseEntity<Void> deleteClientConsent(@AuthenticationPrincipal Gw2AuthUserV2 user, @PathVariable("clientId") UUID clientId) {
        this.applicationClientAccountService.deleteApplicationClientConsent(user.getAccountId(), clientId);
        return ResponseEntity.status(HttpStatus.OK).build();
    }
}
