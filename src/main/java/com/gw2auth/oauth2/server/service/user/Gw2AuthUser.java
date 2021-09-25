package com.gw2auth.oauth2.server.service.user;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Map;

public class Gw2AuthUser implements OAuth2User, OidcUser {

    private final OAuth2User parent;
    private final OidcUser oidcParent;
    private final long accountId;

    public Gw2AuthUser(OAuth2User parent, long accountId) {
        this.parent = parent;
        this.oidcParent = null;
        this.accountId = accountId;
    }

    public Gw2AuthUser(OidcUser parent, long accountId) {
        this.parent = parent;
        this.oidcParent = parent;
        this.accountId = accountId;
    }

    @Override
    public <A> A getAttribute(String name) {
        return this.parent.getAttribute(name);
    }

    @Override
    public Map<String, Object> getAttributes() {
        return this.parent.getAttributes();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.parent.getAuthorities();
    }

    @Override
    public String getName() {
        return Long.toString(this.accountId);
    }

    public OAuth2User getParent() {
        return this.parent;
    }

    public long getAccountId() {
        return this.accountId;
    }

    @Override
    public Map<String, Object> getClaims() {
        return verifyOidcUser().getClaims();
    }

    @Override
    public OidcUserInfo getUserInfo() {
        return verifyOidcUser().getUserInfo();
    }

    @Override
    public OidcIdToken getIdToken() {
        return verifyOidcUser().getIdToken();
    }

    private OidcUser verifyOidcUser() {
        if (this.oidcParent == null) {
            throw new UnsupportedOperationException();
        }

        return this.oidcParent;
    }
}
