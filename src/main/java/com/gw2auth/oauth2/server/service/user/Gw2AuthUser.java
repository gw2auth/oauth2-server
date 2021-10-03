package com.gw2auth.oauth2.server.service.user;

import com.gw2auth.oauth2.server.service.account.AccountFederation;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Map;
import java.util.Objects;

public class Gw2AuthUser implements OAuth2User, OidcUser {

    private final OAuth2User parent;
    private final long accountId;
    private final AccountFederation accountFederation;

    public Gw2AuthUser(OAuth2User parent, long accountId) {
        this(parent, accountId, null);
    }

    public Gw2AuthUser(OAuth2User parent, long accountId, AccountFederation accountFederation) {
        this.parent = parent;
        this.accountId = accountId;
        this.accountFederation = accountFederation;
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

    public AccountFederation getAccountFederation() {
        // this method should only be called from an actual authentication, not within an oauth2 flow
        return Objects.requireNonNull(this.accountFederation);
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
