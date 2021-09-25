package com.gw2auth.oauth2.server.web;

import com.gw2auth.oauth2.server.service.account.AccountFederation;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUser;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;

@RestController
public class AccountController extends AbstractRestController {

    private final AccountService accountService;

    public AccountController(AccountService accountService) {
        this.accountService = accountService;
    }

    @GetMapping(value = "/api/account/federation", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<String> getAccountFederations(@AuthenticationPrincipal Gw2AuthUser user) {
        return this.accountService.getAccountFederations(user.getAccountId()).stream()
                .map(AccountFederation::issuer)
                .collect(Collectors.toList());
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
