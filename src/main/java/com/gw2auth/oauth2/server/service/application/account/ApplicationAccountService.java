package com.gw2auth.oauth2.server.service.application.account;

import java.util.Optional;
import java.util.UUID;

public interface ApplicationAccountService {

    Optional<ApplicationAccount> getApplicationAccount(UUID accountId, UUID applicationId);
}
