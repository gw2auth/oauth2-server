package com.gw2auth.oauth2.server.service.account;

import com.gw2auth.oauth2.server.util.Pair;

import java.util.List;
import java.util.Optional;

public interface AccountService {

    Account getOrCreateAccount(String issuer, String idAtIssuer);

    Optional<Account> getAccount(String issuer, String idAtIssuer);

    AccountFederationSession createNewSession(String issuer, String idAtIssuer);

    AccountFederationSession updateSession(String sessionId, String issuer, String idAtIssuer);

    Optional<Pair<Account, AccountFederation>> getAccountForSession(String sessionId);

    void prepareAddFederation(long accountId, String issuer);
    boolean checkAndDeletePrepareAddFederation(long accountId, String issuer);

    Account addAccountFederationOrReturnExisting(long accountId, String issuer, String idAtIssuer);

    List<AccountFederationWithSessions> getAccountFederationsWithSessions(long accountId);

    boolean deleteAccountFederation(long accountId, String issuer, String idAtIssuer);

    boolean deleteSession(long accountId, String sessionId);

    boolean deleteAccount(long accountId);
}
