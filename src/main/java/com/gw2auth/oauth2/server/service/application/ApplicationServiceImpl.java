package com.gw2auth.oauth2.server.service.application;

import com.gw2auth.oauth2.server.repository.application.ApplicationEntity;
import com.gw2auth.oauth2.server.repository.application.ApplicationRepository;
import com.gw2auth.oauth2.server.service.Clocked;
import com.gw2auth.oauth2.server.service.account.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

@Service
public class ApplicationServiceImpl implements ApplicationService, Clocked {

    private final AccountService accountService;
    private final ApplicationRepository applicationRepository;
    private Clock clock;

    @Autowired
    public ApplicationServiceImpl(AccountService accountService, ApplicationRepository applicationRepository) {
        this.accountService = accountService;
        this.applicationRepository = applicationRepository;
        this.clock = Clock.systemUTC();
    }

    @Override
    public void setClock(Clock clock) {
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    @Transactional
    public Application createApplication(UUID accountId, String displayName) {
        final ApplicationEntity entity = this.applicationRepository.save(new ApplicationEntity(
                UUID.randomUUID(),
                accountId,
                this.clock.instant(),
                displayName
        ));

        this.accountService.log(
                accountId,
                String.format("New application '%s' created", entity.displayName()),
                Map.of("application_id", entity.id())
        );

        return Application.fromEntity(entity);
    }
}
