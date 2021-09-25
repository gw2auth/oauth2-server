package com.gw2auth.oauth2.server.service.account;

import com.gw2auth.oauth2.server.repository.account.AccountEntity;
import com.gw2auth.oauth2.server.repository.account.AccountFederationEntity;
import com.gw2auth.oauth2.server.repository.account.AccountFederationRepository;
import com.gw2auth.oauth2.server.repository.account.AccountRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class AccountServiceImpl implements AccountService {

    private final AccountRepository accountRepository;
    private final AccountFederationRepository accountFederationRepository;

    @Autowired
    public AccountServiceImpl(AccountRepository accountRepository, AccountFederationRepository accountFederationRepository) {
        this.accountRepository = accountRepository;
        this.accountFederationRepository = accountFederationRepository;
    }

    @Override
    public Account getOrCreateAccount(String issuer, String idAtIssuer) {
        return Account.fromEntity(getOrCreateAccountInternal(issuer, idAtIssuer));
    }

    @Override
    @Transactional
    public Account addAccountFederationOrReturnExisting(long accountId, String issuer, String idAtIssuer) {
        final Optional<AccountEntity> optionalAccountEntity = this.accountRepository.findByFederation(issuer, idAtIssuer);
        AccountEntity accountEntity;

        if (optionalAccountEntity.isEmpty()) {
            accountEntity = this.accountRepository.findById(accountId).orElseThrow(IllegalArgumentException::new);

            AccountFederationEntity accountFederationEntity = new AccountFederationEntity(issuer, idAtIssuer, accountId);
            accountFederationEntity = this.accountFederationRepository.save(accountFederationEntity);
        } else {
            accountEntity = optionalAccountEntity.get();
        }

        return Account.fromEntity(accountEntity);
    }

    @Override
    public List<AccountFederation> getAccountFederations(long accountId) {
        return this.accountFederationRepository.findAllByAccountId(accountId).stream()
                .map(AccountFederation::fromEntity)
                .collect(Collectors.toList());
    }

    @Override
    @Transactional
    public boolean deleteAccount(long accountId) {
        this.accountRepository.deleteById(accountId);
        return true;
    }

    @Transactional
    protected AccountEntity getOrCreateAccountInternal(String issuer, String idAtIssuer) {
        final Optional<AccountEntity> optionalAccount = this.accountRepository.findByFederation(issuer, idAtIssuer);
        AccountEntity accountEntity;

        if (optionalAccount.isEmpty()) {
            accountEntity = this.accountRepository.save(new AccountEntity(null, Instant.now()));

            AccountFederationEntity accountFederationEntity = new AccountFederationEntity(issuer, idAtIssuer, accountEntity.id());
            accountFederationEntity = this.accountFederationRepository.save(accountFederationEntity);
        } else {
            accountEntity = optionalAccount.get();
        }

        return accountEntity;
    }
}
