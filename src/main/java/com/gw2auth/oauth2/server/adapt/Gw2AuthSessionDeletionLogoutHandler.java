package com.gw2auth.oauth2.server.adapt;

import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUserV2;
import com.gw2auth.oauth2.server.util.AuthenticationHelper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;


public class Gw2AuthSessionDeletionLogoutHandler implements LogoutHandler {

    private final AccountService accountService;

    public Gw2AuthSessionDeletionLogoutHandler(AccountService accountService) {
        this.accountService = accountService;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        Gw2AuthUserV2 gw2AuthUser = null;

        if (authentication != null) {
            final Object principal = authentication.getPrincipal();

            if (principal instanceof Gw2AuthUserV2 u) {
                gw2AuthUser = u;
            }
        }

        if (gw2AuthUser == null) {
            gw2AuthUser = AuthenticationHelper.getUser(true).orElse(null);
        }

        if (gw2AuthUser != null) {
            final String sessionId = gw2AuthUser.getSessionId();

            if (sessionId != null) {
                this.accountService.deleteSession(gw2AuthUser.getAccountId(), sessionId);
            }
        }
    }
}
