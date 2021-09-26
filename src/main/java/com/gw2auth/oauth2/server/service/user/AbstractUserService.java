package com.gw2auth.oauth2.server.service.user;

import com.gw2auth.oauth2.server.service.account.Account;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.util.AuthenticationHelper;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpSession;

public abstract class AbstractUserService {

    public static final String ADD_FEDERATION_SESSION_KEY = "GW2AUTH_ADD_FEDERATION";

    private final AccountService accountService;

    protected AbstractUserService(AccountService accountService) {
        this.accountService = accountService;
    }

    protected Gw2AuthUser loadUser(OAuth2UserRequest userRequest, OAuth2User user) throws OAuth2AuthenticationException {
        final HttpSession session = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest().getSession(false);
        final String issuer = userRequest.getClientRegistration().getRegistrationId();
        final String idAtIssuer = user.getName();

        final Gw2AuthUser currentlyLoggedInUser = AuthenticationHelper.getUser().orElse(null);
        boolean addFederation = false;

        // check if the user tried to add this federation
        if (session != null) {
            final Object addAuthProviderValue = session.getAttribute(ADD_FEDERATION_SESSION_KEY);
            session.removeAttribute(ADD_FEDERATION_SESSION_KEY);

            if (issuer.equals(addAuthProviderValue)) {
                addFederation = true;
            }
        }

        Account account = null;

        if (addFederation) {
            // if this federation should be added, only allow if the user is currently logged in
            if (currentlyLoggedInUser != null) {
                final Account resultAccount = this.accountService.addAccountFederationOrReturnExisting(currentlyLoggedInUser.getAccountId(), issuer, idAtIssuer);

                // only allow if this federation was not yet linked to another account
                if (resultAccount.id() == currentlyLoggedInUser.getAccountId()) {
                    account = resultAccount;
                }
            }
        } else {
            // if no federation should be added (normal login), only allow if the user is not currently logged in
            if (currentlyLoggedInUser == null) {
                account = this.accountService.getOrCreateAccount(issuer, idAtIssuer);
            }
        }

        if (account == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED));
        }

        return new Gw2AuthUser(user, account.id());
    }
}
