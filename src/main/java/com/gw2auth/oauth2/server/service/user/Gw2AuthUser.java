package com.gw2auth.oauth2.server.service.user;

import com.gw2auth.oauth2.server.util.Pair;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.io.ObjectStreamField;
import java.io.Serial;
import java.io.Serializable;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;

public class Gw2AuthUser implements OAuth2User, OidcUser, Serializable {

    @Serial
    private static final ObjectStreamField[] serialPersistentFields = new ObjectStreamField[]{
            new ObjectStreamField("parent", OAuth2User.class),
            new ObjectStreamField("accountId", long.class),
            new ObjectStreamField("accountFederation", Pair.class)
    };

    private final OAuth2User parent;
    private final long accountId;
    private final Pair<String, String> accountFederation;

    public Gw2AuthUser(OAuth2User parent, long accountId) {
        this(parent, accountId, null);
    }

    public Gw2AuthUser(OAuth2User parent, long accountId, Pair<String, String> accountFederation) {
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

    public Pair<String, String> getAccountFederation() {
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
