package com.gw2auth.oauth2.server.web.account;

import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.user.AbstractUserService;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUser;
import com.gw2auth.oauth2.server.web.AbstractRestController;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.List;
import java.util.stream.Collectors;

@RestController
public class AccountController extends AbstractRestController {

    private final AccountService accountService;
    private final ClientRegistrationRepository clientRegistrationRepository;

    public AccountController(AccountService accountService, ClientRegistrationRepository clientRegistrationRepository) {
        this.accountService = accountService;
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @GetMapping(value = "/api/account/federation", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<AccountFederationResponse> getAccountFederations(@AuthenticationPrincipal Gw2AuthUser user) {
        return this.accountService.getAccountFederations(user.getAccountId()).stream()
                .map(AccountFederationResponse::create)
                .collect(Collectors.toList());
    }

    // I really wouldve liked to make this a POST request, to enable all the security features that are enabled on POST
    // but I realized it's a mess to do so; see https://github.com/w3c/webappsec-csp/issues/8
    // TL;DR: Even if the initial src of the request matches 'self', it is not allowed to redirect to anything not specified
    // in the CSP in the whole chain
    @GetMapping("/api/account/federation/{provider}")
    public ResponseEntity<Void> addAccountFederation(@PathVariable("provider") String provider, HttpServletRequest request, HttpSession session) {
        if (this.clientRegistrationRepository.findByRegistrationId(provider) == null) {
            return ResponseEntity.notFound().build();
        }

        session.setAttribute(AbstractUserService.ADD_FEDERATION_SESSION_KEY, provider);

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
    public boolean deleteAccountFederation(@AuthenticationPrincipal Gw2AuthUser user, @RequestParam("issuer") String issuer, @RequestParam("idAtIssuer") String idAtIssuer) {
        return this.accountService.deleteAccountFederation(user.getAccountId(), issuer, idAtIssuer);
    }

    @DeleteMapping(value = "/api/account", produces = MediaType.APPLICATION_JSON_VALUE)
    public boolean deleteAccount(@AuthenticationPrincipal Gw2AuthUser user) {
        final boolean success = this.accountService.deleteAccount(user.getAccountId());
        if (success) {
            SecurityContextHolder.getContext().setAuthentication(null);
        }

        return success;
    }
}
