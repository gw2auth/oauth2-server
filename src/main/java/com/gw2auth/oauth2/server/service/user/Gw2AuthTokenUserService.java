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

    private static final String REQUEST_ATTRIBUTE_NAME = Gw2AuthTokenUserService.class.getName() + "/" + Gw2AuthUserV2.class.getName();

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
        Gw2AuthUserV2 user = Optional.ofNullable(request.getAttribute(REQUEST_ATTRIBUTE_NAME))
                .filter(Gw2AuthUserV2.class::isInstance)
                .map(Gw2AuthUserV2.class::cast)
                .orElse(null);

        if (user != null) {
            return Optional.of(user);
        }

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
        final Duration timePassedSinceLastJwtCreation = Duration.between(jwt.getIssuedAt(), this.clock.instant());

        byte[] encryptionKeyBytes = this.jwtConverter.readEncryptionKey(jwt).orElse(null);
        Pair<SecretKey, IvParameterSpec> encryptionKey = Optional.ofNullable(encryptionKeyBytes)
                .map(SymEncryption::fromBytes)
                .orElse(null);

        final SessionMetadata currentSessionMetadata = this.sessionMetadataService.extractMetadataFromRequest(request)
                .orElse(null);

        if (accountSession.metadata() != null) {
            // if the saved session in DB has metadata (the user had metadata before),
            // the request must also contain metadata and also an encryption key
            if (currentSessionMetadata == null || encryptionKey == null) {
                this.accountService.deleteSession(account.id(), sessionId);
                return Optional.empty();
            }

            final SessionMetadata originalSessionMetadata = this.sessionMetadataService.decryptMetadata(encryptionKey.v1(), encryptionKey.v2(), accountSession.metadata());

            if (!this.sessionMetadataService.isMetadataPlausible(originalSessionMetadata, currentSessionMetadata, timePassedSinceLastJwtCreation)) {
                this.accountService.deleteSession(account.id(), sessionId);
                return Optional.empty();
            }
        }

        if (!Objects.equals(request.getPathInfo(), Constants.LOGOUT_URL)) {
            // no matter if metadata was known before or not, if it is now known, use them
            final byte[] metadataBytes;

            if (currentSessionMetadata != null) {
                // encryption key might not be there yet (if metadata was not known before)
                if (encryptionKey == null) {
                    encryptionKey = new Pair<>(SymEncryption.generateKey(), SymEncryption.generateIv());
                    encryptionKeyBytes = SymEncryption.toBytes(encryptionKey);
                }

                metadataBytes = this.sessionMetadataService.encryptMetadata(encryptionKey.v1(), encryptionKey.v2(), currentSessionMetadata);
            } else {
                metadataBytes = null;
            }

            final AccountFederationSession updatedSession = this.accountService.updateSession(
                    sessionId,
                    accountFederation.issuer(),
                    accountFederation.idAtIssuer(),
                    metadataBytes
            );

            jwt = this.jwtConverter.writeJWT(updatedSession.id(), encryptionKeyBytes, updatedSession.creationTime(), updatedSession.expirationTime());
            CookieHelper.addCookie(request, AuthenticationHelper.getCurrentResponse().orElseThrow(), Constants.ACCESS_TOKEN_COOKIE_NAME, jwt.getTokenValue(), jwt.getExpiresAt());
        }

        user = new Gw2AuthUserV2(account.id(), accountFederation.issuer(), accountFederation.idAtIssuer(), sessionId, currentSessionMetadata, encryptionKeyBytes);
        request.setAttribute(REQUEST_ATTRIBUTE_NAME, user);

        return Optional.of(user);
    }
}
