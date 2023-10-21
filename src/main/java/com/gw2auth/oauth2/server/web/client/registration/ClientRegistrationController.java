package com.gw2auth.oauth2.server.web.client.registration;

import com.gw2auth.oauth2.server.service.OAuth2ClientApiVersion;
import com.gw2auth.oauth2.server.service.OAuth2ClientType;
import com.gw2auth.oauth2.server.service.application.Application;
import com.gw2auth.oauth2.server.service.application.ApplicationService;
import com.gw2auth.oauth2.server.service.application.client.ApplicationClient;
import com.gw2auth.oauth2.server.service.application.client.ApplicationClientCreation;
import com.gw2auth.oauth2.server.service.application.client.ApplicationClientService;
import com.gw2auth.oauth2.server.service.summary.SummaryService;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUserV2;
import com.gw2auth.oauth2.server.web.AbstractRestController;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.util.Comparator;
import java.util.List;
import java.util.UUID;

@RestController
public class ClientRegistrationController extends AbstractRestController {

    private final ApplicationService applicationService;
    private final ApplicationClientService applicationClientService;
    private final SummaryService summaryService;

    @Autowired
    public ClientRegistrationController(ApplicationService applicationService,
                                        ApplicationClientService applicationClientService,
                                        SummaryService summaryService) {

        this.applicationService = applicationService;
        this.applicationClientService = applicationClientService;
        this.summaryService = summaryService;
    }

    @GetMapping(value = "/api/client/registration", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<ClientRegistrationPrivateResponse> getClientRegistrations(@AuthenticationPrincipal Gw2AuthUserV2 user) {
        return this.applicationClientService.getApplicationClients(user.getAccountId()).stream()
                .map(ClientRegistrationPrivateResponse::create)
                .sorted(Comparator.comparing(ClientRegistrationPrivateResponse::creationTime))
                .toList();
    }

    @GetMapping(value = "/api/client/registration/{clientId}", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> getClientRegistration(@AuthenticationPrincipal Gw2AuthUserV2 user, @PathVariable("clientId") UUID clientId) {
        return fromOptional(
                this.applicationClientService.getApplicationClient(user.getAccountId(), clientId)
                        .map(ClientRegistrationPrivateResponse::create)
        );
    }

    @GetMapping(value = "/api/client/registration/{clientId}/summary", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> getClientRegistrationSummary(@AuthenticationPrincipal Gw2AuthUserV2 user, @PathVariable("clientId") UUID clientId) {
        return fromOptional(
                this.applicationClientService.getApplicationClient(user.getAccountId(), clientId)// ensure to only proceed if owner matches
                        .map((v) -> this.summaryService.getClientSummary(v.id()))
                        .map(ClientRegistrationPrivateSummary::create)
        );
    }

    @PostMapping(value = "/api/client/registration", produces = MediaType.APPLICATION_JSON_VALUE)
    @Transactional
    public ClientRegistrationCreationResponse createClientRegistration(@AuthenticationPrincipal Gw2AuthUserV2 user, @RequestBody ClientRegistrationCreationRequest clientRegistrationCreationRequest) {
        final UUID accountId = user.getAccountId();

        // for now, create application+client as one
        final Application application = this.applicationService.createApplication(accountId, clientRegistrationCreationRequest.displayName());
        final ApplicationClientCreation applicationClientCreation = this.applicationClientService.createApplicationClient(
                user.getAccountId(),
                application.id(),
                clientRegistrationCreationRequest.displayName(),
                clientRegistrationCreationRequest.authorizationGrantTypes(),
                clientRegistrationCreationRequest.redirectUris(),
                OAuth2ClientApiVersion.CURRENT,
                OAuth2ClientType.CONFIDENTIAL
        );

        return new ClientRegistrationCreationResponse(
                ClientRegistrationPrivateResponse.create(applicationClientCreation.client()),
                applicationClientCreation.clientSecret()
        );
    }

    @PutMapping(value = "/api/client/registration/{clientId}/redirect-uris", produces = MediaType.APPLICATION_JSON_VALUE)
    public ClientRegistrationPrivateResponse addRedirectUri(@AuthenticationPrincipal Gw2AuthUserV2 user, @PathVariable("clientId") UUID clientId, @RequestBody String redirectUri) {
        return ClientRegistrationPrivateResponse.create(this.applicationClientService.addRedirectUri(
                user.getAccountId(),
                clientId,
                redirectUri
        ));
    }

    @DeleteMapping(value = "/api/client/registration/{clientId}/redirect-uris", produces = MediaType.APPLICATION_JSON_VALUE)
    public ClientRegistrationPrivateResponse removeRedirectUri(@AuthenticationPrincipal Gw2AuthUserV2 user, @PathVariable("clientId") UUID clientId, @RequestParam("redirectUri") String redirectUri) {
        return ClientRegistrationPrivateResponse.create(this.applicationClientService.removeRedirectUri(
                user.getAccountId(),
                clientId,
                redirectUri
        ));
    }

    @PatchMapping(value = "/api/client/registration/{clientId}/client-secret", produces = MediaType.APPLICATION_JSON_VALUE)
    public ClientRegistrationCreationResponse regenerateClientSecret(@AuthenticationPrincipal Gw2AuthUserV2 user, @PathVariable("clientId") UUID clientId) {
        final ApplicationClientCreation applicationClientCreation = this.applicationClientService.regenerateClientSecret(
                user.getAccountId(),
                clientId
        );

        return new ClientRegistrationCreationResponse(
                ClientRegistrationPrivateResponse.create(applicationClientCreation.client()),
                applicationClientCreation.clientSecret()
        );
    }

    @DeleteMapping("/api/client/registration/{clientId}")
    @Transactional
    public ResponseEntity<Void> deleteClientRegistration(@AuthenticationPrincipal Gw2AuthUserV2 user, @PathVariable("clientId") UUID clientId) {
        final UUID accountId = user.getAccountId();
        final ApplicationClient applicationClient = this.applicationClientService.getApplicationClient(accountId, clientId).orElse(null);

        if (applicationClient == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        // this will delete the client too
        this.applicationService.deleteApplication(accountId, applicationClient.applicationId());

        return ResponseEntity.status(HttpStatus.OK).build();
    }
}
