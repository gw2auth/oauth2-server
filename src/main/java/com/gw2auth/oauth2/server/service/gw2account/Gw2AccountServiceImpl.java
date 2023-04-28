package com.gw2auth.oauth2.server.service.gw2account;

import com.gw2auth.oauth2.server.repository.gw2account.Gw2AccountEntity;
import com.gw2auth.oauth2.server.repository.gw2account.Gw2AccountRepository;
import com.gw2auth.oauth2.server.service.Clocked;
import com.gw2auth.oauth2.server.service.account.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

@Service
public class Gw2AccountServiceImpl implements Gw2AccountService, Clocked {

    private final AccountService accountService;
    private final Gw2AccountRepository gw2AccountRepository;
    private Clock clock;

    @Autowired
    public Gw2AccountServiceImpl(AccountService accountService, Gw2AccountRepository gw2AccountRepository) {
        this.accountService = accountService;
        this.gw2AccountRepository = gw2AccountRepository;
        this.clock = Clock.systemUTC();
    }

    @Override
    public void setClock(Clock clock) {
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    @Transactional
    public Gw2Account getOrCreateGw2Account(UUID accountId, UUID gw2AccountId, String displayName) {
        final Instant now = this.clock.instant();
        final Gw2AccountEntity entity = this.gw2AccountRepository.save(
                accountId,
                gw2AccountId,
                now,
                displayName,
                "A",
                null,
                null
        );

        if (now.truncatedTo(ChronoUnit.SECONDS).equals(entity.creationTime().truncatedTo(ChronoUnit.SECONDS))) {
            this.accountService.log(
                    accountId,
                    String.format("The GW2 Account '%s' was added to your account", entity.displayName()),
                    Map.of("gw2_account_id", gw2AccountId)
            );
        }

        return Gw2Account.fromEntity(entity);
    }

    @Override
    public void updateDisplayName(UUID accountId, UUID gw2AccountId, String displayName) {
        this.gw2AccountRepository.updateDisplayNameByAccountIdAndGw2AccountId(accountId, gw2AccountId, displayName);
    }

    @Override
    public void updateOrderBetween(UUID accountId, UUID gw2AccountId, String first, String second) {
        throw new UnsupportedOperationException();
    }
}
