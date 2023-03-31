package com.gw2auth.oauth2.server.service.user;

import com.gw2auth.oauth2.server.service.account.*;
import com.gw2auth.oauth2.server.service.security.AuthenticationHelper;
import com.gw2auth.oauth2.server.service.security.Gw2AuthInternalJwtConverter;
import com.gw2auth.oauth2.server.service.security.SessionMetadata;
import com.gw2auth.oauth2.server.service.security.SessionMetadataService;
import com.gw2auth.oauth2.server.util.Constants;
import com.gw2auth.oauth2.server.util.CookieHelper;
import com.gw2auth.oauth2.server.util.Pair;
import com.gw2auth.oauth2.server.util.SymEncryption;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

@Service
public class Gw2AuthTokenUserService {

    private final Gw2AuthInternalJwtConverter jwtConverter;
    private final SessionMetadataService sessionMetadataService;
    private final AccountService accountService;
    private Clock clock;

    @Autowired
    public Gw2AuthTokenUserService(Gw2AuthInternalJwtConverter jwtConverter, SessionMetadataService sessionMetadataService, AccountService accountService) {
        this.jwtConverter = jwtConverter;
        this.sessionMetadataService = sessionMetadataService;
        this.accountService = accountService;
        this.clock = Clock.systemUTC();
    }

    public void setClock(Clock clock) {
        this.clock = Objects.requireNonNull(clock);
    }

    public Optional<Gw2AuthUserV2> resolveUserForToken(HttpServletRequest request, String token) {
        Jwt jwt;
        try {
            jwt = this.jwtConverter.readJWT(token);
        } catch (Exception e) {
            return Optional.empty();
        }

        final String sessionId;
        try {
            sessionId = this.jwtConverter.readSessionId(jwt);
        } catch (Exception e) {
            return Optional.empty();
        }

        final Optional<AccountSession> optionalAccountSession = this.accountService.getAccountForSession(sessionId);
        if (optionalAccountSession.isEmpty()) {
            return Optional.empty();
        }

        final AccountSession accountSession  = optionalAccountSession.get();
        final Account account = accountSession.account();
        final AccountFederation accountFederation = accountSession.accountFederation();

        final byte[] encryptionKeyBytes = this.jwtConverter.readEncryptionKey(jwt).orElse(null);
        final Gw2AuthUserV2 user;
        final byte[] metadataBytes;

        if (accountSession.metadata() != null) {
            // if current session has metadata, the request must contain an encryption key
            final Pair<SecretKey, IvParameterSpec> encryptionKey = SymEncryption.fromBytes(Objects.requireNonNull(encryptionKeyBytes));
            final SessionMetadata currentSessionMetadata = this.sessionMetadataService.extractMetadataFromRequest(request)
                    .orElse(null);

            if (currentSessionMetadata == null) {
                this.accountService.deleteSession(account.id(), sessionId);
                return Optional.empty();
            }

            final SessionMetadata originalSessionMetadata = this.sessionMetadataService.decryptMetadata(encryptionKey.v1(), encryptionKey.v2(), accountSession.metadata());
            final Duration timePassed = Duration.between(jwt.getIssuedAt(), this.clock.instant());

            if (!this.sessionMetadataService.isMetadataPlausible(originalSessionMetadata, currentSessionMetadata, timePassed)) {
                this.accountService.deleteSession(account.id(), sessionId);
                return Optional.empty();
            }

            user = new Gw2AuthUserV2(account.id(), accountFederation.issuer(), accountFederation.idAtIssuer(), sessionId, currentSessionMetadata, encryptionKeyBytes);
            metadataBytes = this.sessionMetadataService.encryptMetadata(encryptionKey.v1(), encryptionKey.v2(), currentSessionMetadata);
        } else {
            user = new Gw2AuthUserV2(account.id(), accountFederation.issuer(), accountFederation.idAtIssuer(), sessionId, null, null);
            metadataBytes = null;
        }

        if (!Objects.equals(request.getPathInfo(), Constants.LOGOUT_URL)) {
            final AccountFederationSession updatedSession = this.accountService.updateSession(
                    user.getSessionId(),
                    user.getIssuer(),
                    user.getIdAtIssuer(),
                    metadataBytes
            );

            jwt = this.jwtConverter.writeJWT(updatedSession.id(), encryptionKeyBytes, updatedSession.creationTime(), updatedSession.expirationTime());
            CookieHelper.addCookie(request, AuthenticationHelper.getCurrentResponse().orElseThrow(), Constants.ACCESS_TOKEN_COOKIE_NAME, jwt.getTokenValue(), jwt.getExpiresAt());
        }

        return Optional.of(user);
    }
}
