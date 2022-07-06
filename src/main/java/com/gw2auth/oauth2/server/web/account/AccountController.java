package com.gw2auth.oauth2.server.web.account;

import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.summary.SummaryService;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUserV2;
import com.gw2auth.oauth2.server.web.AbstractRestController;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import java.util.stream.Collectors;

@RestController
public class AccountController extends AbstractRestController {

    private final AccountService accountService;
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final SummaryService summaryService;

    @Autowired
    public AccountController(AccountService accountService, ClientRegistrationRepository clientRegistrationRepository, SummaryService summaryService) {
        this.accountService = accountService;
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.summaryService = summaryService;
    }

    @GetMapping(value = "/api/account/summary", produces = MediaType.APPLICATION_JSON_VALUE)
    public AccountSummaryResponse getAccountSummary(@AuthenticationPrincipal Gw2AuthUserV2 user) {
        return AccountSummaryResponse.create(this.summaryService.getAccountSummary(user.getAccountId()));
    }

    @GetMapping(value = "/api/account/federation", produces = MediaType.APPLICATION_JSON_VALUE)
    public AccountFederationsResponse getAccountFederations(@AuthenticationPrincipal Gw2AuthUserV2 user) {
        return new AccountFederationsResponse(
                new AccountFederationResponse(user.getAccountFederation().v1(), user.getAccountFederation().v2()),
                this.accountService.getAccountFederations(user.getAccountId()).stream()
                        .map(AccountFederationResponse::create)
                        .collect(Collectors.toList())
        );
    }

    @GetMapping(value = "/api/account/session", produces = MediaType.APPLICATION_JSON_VALUE)
    public AccountSessionsResponse getAccountSessions(@AuthenticationPrincipal Gw2AuthUserV2 user) {
        return new AccountSessionsResponse(
                user.getSessionId(),
                this.accountService.getSessions(user.getAccountId()).stream()
                        .map(AccountSessionResponse::create)
                        .collect(Collectors.toList())
        );
    }

    // I really wouldve liked to make this a POST request, to enable all the security features that are enabled on POST
    // but I realized it's a mess to do so; see https://github.com/w3c/webappsec-csp/issues/8
    // TL;DR: Even if the initial src of the request matches 'self', it is not allowed to redirect to anything not specified
    // in the CSP in the whole chain
    @GetMapping("/api/account/federation/{provider}")
    public ResponseEntity<Void> addAccountFederation(@AuthenticationPrincipal Gw2AuthUserV2 user, @PathVariable("provider") String provider, HttpServletRequest request) {
        if (this.clientRegistrationRepository.findByRegistrationId(provider) == null) {
            return ResponseEntity.notFound().build();
        }

        this.accountService.prepareAddFederation(user.getAccountId(), provider);

        return ResponseEntity.status(HttpStatus.FOUND)
                .location(
                        UriComponentsBuilder
                                .fromUriString(request.getRequestURI())
                                .replacePath("/oauth2/authorization/")
                                .path(provider)
                                .replaceQuery(null)
                                .build()
                                .toUri()
                )
                .build();
    }

    @DeleteMapping(value = "/api/account/federation", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Void> deleteAccountFederation(@AuthenticationPrincipal Gw2AuthUserV2 user, @RequestParam("issuer") String issuer, @RequestParam("idAtIssuer") String idAtIssuer) {
        if (user.getAccountFederation().v1().equals(issuer) && user.getAccountFederation().v2().equals(idAtIssuer)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }

        final boolean success = this.accountService.deleteAccountFederation(user.getAccountId(), issuer, idAtIssuer);
        if (success) {
            return ResponseEntity.ok().build();
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @DeleteMapping(value = "/api/account/session", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Void> deleteSession(@AuthenticationPrincipal Gw2AuthUserV2 user, @RequestParam("id") String sessionId) {
        if (user.getSessionId().equals(sessionId)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }

        final boolean success = this.accountService.deleteSession(user.getAccountId(), sessionId);
        if (success) {
            return ResponseEntity.ok().build();
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @DeleteMapping(value = "/api/account", produces = MediaType.APPLICATION_JSON_VALUE)
    public boolean deleteAccount(@AuthenticationPrincipal Gw2AuthUserV2 user) {
        final boolean success = this.accountService.deleteAccount(user.getAccountId());
        if (success) {
            SecurityContextHolder.getContext().setAuthentication(null);
        }

        return success;
    }
}
