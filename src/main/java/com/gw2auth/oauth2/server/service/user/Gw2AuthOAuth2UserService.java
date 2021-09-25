package com.gw2auth.oauth2.server.service.user;

import com.gw2auth.oauth2.server.service.account.Account;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.util.AuthenticationHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class Gw2AuthOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final OAuth2UserService<OAuth2UserRequest, OAuth2User> parent;
    private final AccountService accountService;

    public Gw2AuthOAuth2UserService(OAuth2UserService<OAuth2UserRequest, OAuth2User> parent, AccountService accountService) {
        this.parent = parent;
        this.accountService = accountService;
    }

    @Autowired
    public Gw2AuthOAuth2UserService(AccountService accountService) {
        this(new DefaultOAuth2UserService(), accountService);
    }

    @Override
    public Gw2AuthUser loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        final OAuth2User user = this.parent.loadUser(userRequest);

        final String issuer = userRequest.getClientRegistration().getRegistrationId();
        final String id = user.getName();

        final Account account = AuthenticationHelper.getUser()
                .map((alreadyLoggedInUser) -> this.accountService.addAccountFederationOrReturnExisting(alreadyLoggedInUser.getAccountId(), issuer, id))
                .orElseGet(() -> this.accountService.getOrCreateAccount(issuer, id));

        return new Gw2AuthUser(user, account.id());
    }
}
