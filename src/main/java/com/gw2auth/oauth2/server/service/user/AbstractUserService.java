package com.gw2auth.oauth2.server.service.user;

import com.gw2auth.oauth2.server.service.account.Account;
import com.gw2auth.oauth2.server.service.account.AccountFederationSession;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.security.AuthenticationHelper;
import com.gw2auth.oauth2.server.service.security.SessionMetadata;
import com.gw2auth.oauth2.server.service.security.SessionMetadataService;
import com.gw2auth.oauth2.server.util.Pair;
import com.gw2auth.oauth2.server.util.SymEncryption;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.user.OAuth2User;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.util.Objects;
import java.util.Optional;

public abstract class AbstractUserService {

    private final AccountService accountService;
    private final SessionMetadataService sessionMetadataService;

    protected AbstractUserService(AccountService accountService, SessionMetadataService sessionMetadataService) {
        this.accountService = accountService;
        this.sessionMetadataService = sessionMetadataService;
    }

    protected Gw2AuthLoginUser loadUser(OAuth2UserRequest userRequest, OAuth2User user) throws OAuth2AuthenticationException {
        final String issuer = userRequest.getClientRegistration().getRegistrationId();
        final String idAtIssuer = user.getName();

        final Gw2AuthUserV2 currentlyLoggedInUser = AuthenticationHelper.getUser(true).orElse(null);
        SessionMetadata sessionMetadata = null;
        Pair<SecretKey, IvParameterSpec> encryptionKey = null;
        Account account = null;

        if (currentlyLoggedInUser != null) {
            sessionMetadata = currentlyLoggedInUser.getSessionMetadata().orElse(null);
            encryptionKey = currentlyLoggedInUser.getEncryptionKey()
                    .map(SymEncryption::fromBytes)
                    .orElse(null);

            if (this.accountService.checkAndDeletePrepareAddFederation(currentlyLoggedInUser.getAccountId(), issuer)) {
                final Account resultAccount = this.accountService.addAccountFederationOrReturnExisting(currentlyLoggedInUser.getAccountId(), issuer, idAtIssuer);

                // only allow if this federation was not yet linked to another account
                if (Objects.equals(resultAccount.id(), currentlyLoggedInUser.getAccountId())) {
                    account = resultAccount;
                }
            }

            // dont allow logins that were not originated from an add federation attempt if already logged in
            // (account will be null and exception thrown later in that case)
        } else {
            account = this.accountService.getOrCreateAccount(issuer, idAtIssuer);
        }

        if (account == null) {
            // if account is null here it means that there was an existing login but the new login was NOT
            // coming from an add federation request
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED));
        }

        if (sessionMetadata == null) {
            sessionMetadata = AuthenticationHelper.getCurrentRequest()
                    .flatMap(this.sessionMetadataService::extractMetadataFromRequest)
                    .orElse(null);
        }

        final byte[] sessionMetadataBytes;

        if (sessionMetadata != null) {
            if (encryptionKey == null) {
                encryptionKey = new Pair<>(SymEncryption.generateKey(), SymEncryption.generateIv());
            }

            sessionMetadataBytes = this.sessionMetadataService.encryptMetadata(encryptionKey.v1(), encryptionKey.v2(), sessionMetadata);
        } else {
            encryptionKey = null;
            sessionMetadataBytes = null;
        }

        final AccountFederationSession session;
        if (currentlyLoggedInUser == null) {
            session = this.accountService.createNewSession(issuer, idAtIssuer, sessionMetadataBytes);
        } else {
            session = this.accountService.updateSession(currentlyLoggedInUser.getSessionId(), issuer, idAtIssuer, sessionMetadataBytes);
        }

        final byte[] encryptionKeyBytes = Optional.ofNullable(encryptionKey)
                .map(SymEncryption::toBytes)
                .orElse(null);

        return new Gw2AuthLoginUser(user, account.id(), session, encryptionKeyBytes);
    }
}
