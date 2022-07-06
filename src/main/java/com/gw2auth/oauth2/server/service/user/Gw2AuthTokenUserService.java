package com.gw2auth.oauth2.server.service.user;

import com.gw2auth.oauth2.server.adapt.Gw2AuthInternalJwtConverter;
import com.gw2auth.oauth2.server.service.account.Account;
import com.gw2auth.oauth2.server.service.account.AccountFederation;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.util.Pair;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class Gw2AuthTokenUserService {

    private final Gw2AuthInternalJwtConverter jwtConverter;
    private final AccountService accountService;

    @Autowired
    public Gw2AuthTokenUserService(Gw2AuthInternalJwtConverter jwtConverter, AccountService accountService) {
        this.jwtConverter = jwtConverter;
        this.accountService = accountService;
    }

    public Optional<Gw2AuthUserV2> resolveUserForToken(String token) {
        final String sessionId;
        try {
            sessionId = this.jwtConverter.readSessionId(this.jwtConverter.readJWT(token));
        } catch (Exception e) {
            return Optional.empty();
        }

        final Optional<Pair<Account, AccountFederation>> optionalAccount = this.accountService.getAccountForSession(sessionId);
        if (optionalAccount.isEmpty()) {
            return Optional.empty();
        }

        final Pair<Account, AccountFederation> accountAndFederation = optionalAccount.get();
        return Optional.of(new Gw2AuthUserV2(accountAndFederation.v1().id(), accountAndFederation.v2().issuer(), accountAndFederation.v2().idAtIssuer(), sessionId));
    }
}
