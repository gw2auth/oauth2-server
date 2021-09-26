package com.gw2auth.oauth2.server.service.user;

import com.gw2auth.oauth2.server.service.account.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

@Service
public class Gw2AuthOidcUserService extends AbstractUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    private final OAuth2UserService<OidcUserRequest, OidcUser> parent;

    public Gw2AuthOidcUserService(AccountService accountService, OAuth2UserService<OidcUserRequest, OidcUser> parent) {
        super(accountService);
        this.parent = parent;
    }

    @Autowired
    public Gw2AuthOidcUserService(AccountService accountService) {
        this(accountService, new OidcUserService());
    }

    @Override
    public Gw2AuthUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        return loadUser(userRequest, this.parent.loadUser(userRequest));
    }
}
