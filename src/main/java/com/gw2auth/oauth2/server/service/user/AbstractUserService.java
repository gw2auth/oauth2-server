package com.gw2auth.oauth2.server.service.user;

import com.gw2auth.oauth2.server.service.account.Account;
import com.gw2auth.oauth2.server.service.account.AccountFederationSession;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.security.AuthenticationHelper;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Objects;

public abstract class AbstractUserService {

    private final AccountService accountService;

    protected AbstractUserService(AccountService accountService) {
        this.accountService = accountService;
    }

    protected Gw2AuthLoginUser loadUser(OAuth2UserRequest userRequest, OAuth2User user) throws OAuth2AuthenticationException {
        final String issuer = userRequest.getClientRegistration().getRegistrationId();
        final String idAtIssuer = user.getName();

        final Gw2AuthUserV2 currentlyLoggedInUser = AuthenticationHelper.getUser(true).orElse(null);
        Account account = null;

        if (currentlyLoggedInUser != null) {
            if (this.accountService.checkAndDeletePrepareAddFederation(currentlyLoggedInUser.getAccountId(), issuer)) {
                final Account resultAccount = this.accountService.addAccountFederationOrReturnExisting(currentlyLoggedInUser.getAccountId(), issuer, idAtIssuer);

                // only allow if this federation was not yet linked to another account
                if (Objects.equals(resultAccount.id(), currentlyLoggedInUser.getAccountId())) {
                    account = resultAccount;
                }
            }

            // dont allow logins that were not originated from an add federation attempt if already logged
        } else {
            account = this.accountService.getOrCreateAccount(issuer, idAtIssuer);
        }

        if (account == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED));
        }

        final AccountFederationSession session;
        if (currentlyLoggedInUser == null) {
            session = this.accountService.createNewSession(issuer, idAtIssuer);
        } else {
            session = this.accountService.updateSession(currentlyLoggedInUser.getSessionId(), issuer, idAtIssuer);
        }

        return new Gw2AuthLoginUser(user, account.id(), session);
    }
}
