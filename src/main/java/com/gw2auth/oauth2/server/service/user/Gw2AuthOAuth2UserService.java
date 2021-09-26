package com.gw2auth.oauth2.server.service.user;

import com.gw2auth.oauth2.server.service.account.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class Gw2AuthOAuth2UserService extends AbstractUserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final OAuth2UserService<OAuth2UserRequest, OAuth2User> parent;

    public Gw2AuthOAuth2UserService(AccountService accountService, OAuth2UserService<OAuth2UserRequest, OAuth2User> parent) {
        super(accountService);
        this.parent = parent;
    }

    @Autowired
    public Gw2AuthOAuth2UserService(AccountService accountService) {
        this(accountService, new DefaultOAuth2UserService());
    }

    @Override
    public Gw2AuthUser loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        return loadUser(userRequest, this.parent.loadUser(userRequest));
    }
}
