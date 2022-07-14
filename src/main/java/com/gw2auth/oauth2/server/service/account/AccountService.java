package com.gw2auth.oauth2.server.service.account;

import com.gw2auth.oauth2.server.util.Pair;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AccountService {

    Account getOrCreateAccount(String issuer, String idAtIssuer);

    Optional<Account> getAccount(String issuer, String idAtIssuer);

    AccountFederationSession createNewSession(String issuer, String idAtIssuer);

    AccountFederationSession updateSession(String sessionId, String issuer, String idAtIssuer);

    Optional<Pair<Account, AccountFederation>> getAccountForSession(String sessionId);

    void prepareAddFederation(UUID accountId, String issuer);
    boolean checkAndDeletePrepareAddFederation(UUID accountId, String issuer);

    Account addAccountFederationOrReturnExisting(UUID accountId, String issuer, String idAtIssuer);

    List<AccountFederationWithSessions> getAccountFederationsWithSessions(UUID accountId);

    boolean deleteAccountFederation(UUID accountId, String issuer, String idAtIssuer);

    boolean deleteSession(UUID accountId, String sessionId);

    boolean deleteAccount(UUID accountId);
}
