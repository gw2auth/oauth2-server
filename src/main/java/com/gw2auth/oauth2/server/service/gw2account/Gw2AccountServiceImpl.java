package com.gw2auth.oauth2.server.service.gw2account;

import com.gw2auth.oauth2.server.repository.gw2account.Gw2AccountEntity;
import com.gw2auth.oauth2.server.repository.gw2account.Gw2AccountRepository;
import com.gw2auth.oauth2.server.repository.gw2account.Gw2AccountWithApiTokenEntity;
import com.gw2auth.oauth2.server.repository.gw2account.Gw2AccountWithOptionalApiTokenEntity;
import com.gw2auth.oauth2.server.service.Clocked;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.gw2account.apitoken.Gw2AccountApiToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

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
    public Gw2Account getOrCreateGw2Account(UUID accountId, UUID gw2AccountId, String gw2AccountName, String displayName) {
        final Instant now = this.clock.instant();
        final Gw2AccountEntity entity = this.gw2AccountRepository.save(
                accountId,
                gw2AccountId,
                gw2AccountName,
                now,
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
    public List<Gw2AccountWithOptionalApiToken> getWithOptionalApiTokens(UUID accountId, Collection<UUID> gw2AccountIds) {
        return this.gw2AccountRepository.findAllWithOptionalTokenByAccountIdAndGw2AccountIds(accountId, gw2AccountIds).stream()
                .map(Gw2AccountServiceImpl::mapWithOptionalToken)
                .toList();
    }

    @Override
    public List<Gw2AccountWithApiToken> getWithApiTokens(UUID accountId) {
        return this.gw2AccountRepository.findAllWithTokenByAccountId(accountId).stream()
                .map(Gw2AccountServiceImpl::mapWithToken)
                .toList();
    }

    private static Gw2AccountWithApiToken mapWithToken(Gw2AccountWithApiTokenEntity entity) {
        final Gw2Account account = Gw2Account.fromEntity(entity.account());
        final Gw2AccountApiToken apiToken = Gw2AccountApiToken.fromEntity(entity.token());

        return new Gw2AccountWithApiToken(account, apiToken);
    }

    private static Gw2AccountWithOptionalApiToken mapWithOptionalToken(Gw2AccountWithOptionalApiTokenEntity entity) {
        final Gw2Account account = Gw2Account.fromEntity(entity.account());
        final Gw2AccountApiToken apiToken =  entity.optionalToken()
                .map(Gw2AccountApiToken::fromEntity)
                .orElse(null);

        return new Gw2AccountWithOptionalApiToken(account, apiToken);
    }
}
