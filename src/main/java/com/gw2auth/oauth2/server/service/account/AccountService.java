package com.gw2auth.oauth2.server.service.account;

import java.util.List;

public interface AccountService {

    Account getOrCreateAccount(String issuer, String idAtIssuer);

    Account addAccountFederationOrReturnExisting(long accountId, String issuer, String idAtIssuer);

    List<AccountFederation> getAccountFederations(long accountId);

    boolean deleteAccount(long accountId);
}
