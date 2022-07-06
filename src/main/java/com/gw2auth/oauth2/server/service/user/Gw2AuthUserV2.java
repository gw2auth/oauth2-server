package com.gw2auth.oauth2.server.service.user;

import com.gw2auth.oauth2.server.util.Pair;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.io.ObjectStreamField;
import java.io.Serial;
import java.io.Serializable;
import java.security.Principal;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class Gw2AuthUserV2 implements OAuth2User, Principal, AuthenticatedPrincipal, Serializable {

    @Serial
    private static final ObjectStreamField[] serialPersistentFields = new ObjectStreamField[]{
            new ObjectStreamField("accountId", long.class),
            new ObjectStreamField("accountFederation", Pair.class)
    };

    private final long accountId;
    private final Pair<String, String> accountFederation;
    private final String sessionId;

    public Gw2AuthUserV2(long accountId, String issuer, String idAtIssuer) {
        this(accountId, issuer, idAtIssuer, null);
    }

    public Gw2AuthUserV2(long accountId, String issuer, String idAtIssuer, String sessionId) {
        this.accountId = accountId;
        this.accountFederation = new Pair<>(issuer, idAtIssuer);
        this.sessionId = sessionId;
    }

    public long getAccountId() {
        return this.accountId;
    }

    public String getIssuer() {
        return getAccountFederation().v1();
    }

    public String getIdAtIssuer() {
        return getAccountFederation().v2();
    }

    public Pair<String, String> getAccountFederation() {
        // this method should only be called from an actual authentication, not within an oauth2 flow
        return Objects.requireNonNull(this.accountFederation);
    }

    public String getSessionId() {
        return this.sessionId;
    }

    @Override
    public String getName() {
        return Long.toString(this.accountId);
    }

    @Override
    public Map<String, Object> getAttributes() {
        return Map.of();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("USER"));
    }
}
