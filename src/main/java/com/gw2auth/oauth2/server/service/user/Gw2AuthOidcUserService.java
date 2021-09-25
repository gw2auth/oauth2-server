package com.gw2auth.oauth2.server.service.user;

import com.gw2auth.oauth2.server.service.account.Account;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.util.AuthenticationHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

@Service
public class Gw2AuthOidcUserService extends OidcUserService {

    private final AccountService accountService;

    @Autowired
    public Gw2AuthOidcUserService(AccountService accountService) {
        this.accountService = accountService;
    }

    @Override
    public Gw2AuthUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        final OidcUser user = super.loadUser(userRequest);

        final String issuer = userRequest.getClientRegistration().getRegistrationId();
        final String id = user.getName();

        final Account account = AuthenticationHelper.getUser()
                .map((alreadyLoggedInUser) -> this.accountService.addAccountFederationOrReturnExisting(alreadyLoggedInUser.getAccountId(), issuer, id))
                .orElseGet(() -> this.accountService.getOrCreateAccount(issuer, id));

        return new Gw2AuthUser(user, account.id());
    }
}
