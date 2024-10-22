package com.gw2auth.oauth2.server.web.account;

import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUserV2;
import com.gw2auth.oauth2.server.web.AbstractRestController;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

@RestController
public class AccountController extends AbstractRestController {

    private final AccountService accountService;
    private final ClientRegistrationRepository clientRegistrationRepository;

    @Autowired
    public AccountController(AccountService accountService, ClientRegistrationRepository clientRegistrationRepository) {
        this.accountService = accountService;
        this.clientRegistrationRepository = clientRegistrationRepository;
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
                                .replacePath("/auth/oauth2/authorization/")
                                .path(provider)
                                .replaceQuery(null)
                                .queryParam("add", "true")
                                .build()
                                .toUri()
                )
                .build();
    }
}
