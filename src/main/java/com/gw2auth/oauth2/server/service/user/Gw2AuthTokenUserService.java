package com.gw2auth.oauth2.server.service.user;

import com.gw2auth.oauth2.server.service.account.Account;
import com.gw2auth.oauth2.server.service.account.AccountFederation;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.security.Gw2AuthInternalJwtConverter;
import com.gw2auth.oauth2.server.service.security.SessionMetadata;
import com.gw2auth.oauth2.server.service.security.SessionMetadataService;
import com.gw2auth.oauth2.server.util.Pair;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
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
        final Jwt jwt;
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

        final Optional<Pair<Account, AccountFederation>> optionalAccount = this.accountService.getAccountForSession(sessionId);
        if (optionalAccount.isEmpty()) {
            return Optional.empty();
        }

        final Pair<Account, AccountFederation> accountAndFederation = optionalAccount.get();
        final Account account = accountAndFederation.v1();
        final AccountFederation accountFederation = accountAndFederation.v2();

        if (request != null) {
            final SessionMetadata originalSessionMetadata = this.jwtConverter.readSessionMetadata(jwt)
                    .flatMap(this.sessionMetadataService::extractMetadataFromMap)
                    .orElse(null);

            final SessionMetadata currentSessionMetadata = this.sessionMetadataService.extractMetadataFromRequest(request)
                    .orElse(null);

            if (originalSessionMetadata != null) {
                if (currentSessionMetadata == null) {
                    this.accountService.deleteSession(account.id(), sessionId);
                    return Optional.empty();
                }

                final Duration timePassed = Duration.between(jwt.getIssuedAt(), this.clock.instant());
                if (!this.sessionMetadataService.isMetadataPlausible(originalSessionMetadata, currentSessionMetadata, timePassed)) {
                    this.accountService.deleteSession(account.id(), sessionId);
                    return Optional.empty();
                }
            }
        }

        return Optional.of(new Gw2AuthUserV2(account.id(), accountFederation.issuer(), accountFederation.idAtIssuer(), sessionId));
    }
}
