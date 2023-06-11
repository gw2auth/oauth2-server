package com.gw2auth.oauth2.server.service.application.client.account;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ApplicationClientAccountService {

    Optional<ApplicationClientAccount> getApplicationClientAccount(UUID accountId, UUID applicationClientId);
    List<ApplicationClientAccount> getApplicationClientAccounts(UUID accountId);
    void deleteApplicationClientConsent(UUID accountId, UUID applicationClientId);
}
