package com.gw2auth.oauth2.server.service.user;

import com.gw2auth.oauth2.server.service.account.AccountFederationSession;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Map;
import java.util.UUID;

public record Gw2AuthLoginUser(OAuth2User parent, UUID accountId, AccountFederationSession session) implements OAuth2User, OidcUser {

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
        return this.accountId.toString();
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
        if (this.parent instanceof OidcUser) {
            return (OidcUser) this.parent;
        }

        throw new UnsupportedOperationException();
    }
}
