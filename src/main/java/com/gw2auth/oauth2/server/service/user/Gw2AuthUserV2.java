package com.gw2auth.oauth2.server.service.user;

import com.gw2auth.oauth2.server.service.security.SessionMetadata;
import com.gw2auth.oauth2.server.util.Pair;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.io.ObjectStreamField;
import java.io.Serial;
import java.io.Serializable;
import java.security.Principal;
import java.time.Instant;
import java.util.*;

public class Gw2AuthUserV2 implements OAuth2User, Principal, AuthenticatedPrincipal, Serializable {

    @Serial
    private static final ObjectStreamField[] serialPersistentFields = new ObjectStreamField[]{
            new ObjectStreamField("accountId", UUID.class),
            new ObjectStreamField("accountFederation", Pair.class)
    };

    private final UUID accountId;
    private final Pair<String, String> accountFederation;
    private final String sessionId;
    private final SessionMetadata sessionMetadata;
    private final Instant sessionCreationTime;
    private final byte[] encryptionKey;

    public Gw2AuthUserV2(UUID accountId, String issuer, String idAtIssuer) {
        this(accountId, issuer, idAtIssuer, null, null, null, null);
    }

    public Gw2AuthUserV2(UUID accountId, String issuer, String idAtIssuer, String sessionId, SessionMetadata sessionMetadata, Instant sessionCreationTime, byte[] encryptionKey) {
        this.accountId = accountId;
        this.accountFederation = new Pair<>(issuer, idAtIssuer);
        this.sessionId = sessionId;
        this.sessionMetadata = sessionMetadata;
        this.sessionCreationTime = sessionCreationTime;
        this.encryptionKey = encryptionKey;
    }

    public UUID getAccountId() {
        return this.accountId;
    }

    public String getIssuer() {
        return getAccountFederation().v1();
    }

    public String getIdAtIssuer() {
        return getAccountFederation().v2();
    }

    private Pair<String, String> getAccountFederation() {
        // this method should only be called from an actual authentication, not within an oauth2 flow
        return Objects.requireNonNull(this.accountFederation);
    }

    public String getSessionId() {
        return this.sessionId;
    }

    public Optional<SessionMetadata> getSessionMetadata() {
        // empty if session has no metadata or if not in actual authentication (oauth2 server side context)
        return Optional.ofNullable(this.sessionMetadata);
    }

    public Optional<Instant> getSessionCreationTime() {
        // empty if not in actual authentication (oauth2 server side context)
        return Optional.ofNullable(this.sessionCreationTime);
    }

    public Optional<byte[]> getEncryptionKey() {
        // empty if session has no metadata or if not in actual authentication (oauth2 server side context)
        return Optional.ofNullable(this.encryptionKey);
    }

    @Override
    public String getName() {
        return this.accountId.toString();
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
