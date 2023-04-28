package com.gw2auth.oauth2.server.service.application.account;

import com.gw2auth.oauth2.server.repository.application.account.ApplicationAccountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

@Service
public class ApplicationAccountServiceImpl implements ApplicationAccountService {

    private final ApplicationAccountRepository applicationAccountRepository;

    @Autowired
    public ApplicationAccountServiceImpl(ApplicationAccountRepository applicationAccountRepository) {
        this.applicationAccountRepository = applicationAccountRepository;
    }

    @Override
    public Optional<ApplicationAccount> getApplicationAccount(UUID accountId, UUID applicationId) {
        return this.applicationAccountRepository.findWithSubByApplicationIdAndAccountId(applicationId, accountId)
                .map(ApplicationAccount::fromEntity);
    }
}
