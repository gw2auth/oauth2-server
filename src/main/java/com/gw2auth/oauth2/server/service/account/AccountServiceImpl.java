package com.gw2auth.oauth2.server.service.account;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.model.S3Object;
import com.gw2auth.oauth2.server.repository.account.*;
import com.gw2auth.oauth2.server.service.Clocked;
import com.gw2auth.oauth2.server.util.Pair;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@Service
@EnableScheduling
public class AccountServiceImpl implements AccountService, Clocked {

    private static final Logger LOG = LoggerFactory.getLogger(AccountServiceImpl.class);

    private final AccountRepository accountRepository;
    private final AccountFederationRepository accountFederationRepository;
    private final AccountFederationSessionRepository accountFederationSessionRepository;
    private final AmazonS3 s3;
    private final String bucket;
    private final String prefix;
    private Clock clock;

    @Autowired
    public AccountServiceImpl(AccountRepository accountRepository,
                              AccountFederationRepository accountFederationRepository,
                              AccountFederationSessionRepository accountFederationSessionRepository,
                              @Qualifier("oauth2-add-federation-s3-client") AmazonS3 s3,
                              @Value("${com.gw2auth.oauth2.addfederation.s3.bucket}") String bucket,
                              @Value("${com.gw2auth.oauth2.addfederation.s3.prefix}") String prefix) {

        this.accountRepository = accountRepository;
        this.accountFederationRepository = accountFederationRepository;
        this.accountFederationSessionRepository = accountFederationSessionRepository;
        this.s3 = s3;
        this.bucket = bucket;
        this.prefix = prefix;
        this.clock = Clock.systemUTC();
    }

    @Override
    public void setClock(Clock clock) {
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    @Transactional
    public Account getOrCreateAccount(String issuer, String idAtIssuer) {
        return Account.fromEntity(getOrCreateAccountInternal(issuer, idAtIssuer));
    }

    @Override
    public Optional<Account> getAccount(String issuer, String idAtIssuer) {
        return this.accountRepository.findByFederation(issuer, idAtIssuer).map(Account::fromEntity);
    }

    @Override
    public AccountFederationSession createNewSession(String issuer, String idAtIssuer, byte[] metadata) {
        final Instant now = this.clock.instant();
        final byte[] sessionIdBytes = new byte[128];
        new SecureRandom().nextBytes(sessionIdBytes);

        final AccountFederationSessionEntity entity = this.accountFederationSessionRepository.save(new AccountFederationSessionEntity(
                Base64.getEncoder().withoutPadding().encodeToString(sessionIdBytes),
                issuer,
                idAtIssuer,
                metadata,
                now,
                now.plus(Duration.ofDays(30L))
        ));

        return AccountFederationSession.fromEntity(entity);
    }

    @Override
    public AccountFederationSession updateSession(String sessionId, String issuer, String idAtIssuer, byte[] metadata) {
        final Instant now = this.clock.instant();
        final AccountFederationSessionEntity entity = this.accountFederationSessionRepository.updateSession(
                sessionId,
                issuer,
                idAtIssuer,
                metadata,
                now,
                now.plus(Duration.ofDays(30L))
        );

        return AccountFederationSession.fromEntity(entity);
    }

    @Override
    public Optional<AccountSession> getAccountForSession(String sessionId) {
        return this.accountRepository.findByFederationSession(sessionId, this.clock.instant()).map(AccountSession::fromEntity);
    }

    @Override
    public void prepareAddFederation(UUID accountId, String issuer) {
        this.s3.putObject(this.bucket, this.prefix + accountId, issuer);
    }

    @Override
    public boolean checkAndDeletePrepareAddFederation(UUID accountId, String issuer) {
        try (S3Object s3Object = this.s3.getObject(this.bucket, this.prefix + accountId)) {
            this.s3.deleteObject(this.bucket, this.prefix + accountId);

            try (InputStream in = s3Object.getObjectContent()) {
                return new String(in.readAllBytes(), StandardCharsets.UTF_8).equals(issuer);
            }
        } catch (AmazonServiceException | IOException e) {
            return false;
        }
    }

    @Override
    @Transactional
    public Account addAccountFederationOrReturnExisting(UUID accountId, String issuer, String idAtIssuer) {
        final Optional<AccountEntity> optionalAccountEntity = this.accountRepository.findByFederation(issuer, idAtIssuer);
        AccountEntity accountEntity;

        if (optionalAccountEntity.isEmpty()) {
            accountEntity = this.accountRepository.findById(accountId).orElseThrow(IllegalArgumentException::new);

            AccountFederationEntity accountFederationEntity = new AccountFederationEntity(issuer, idAtIssuer, accountId);
            accountFederationEntity = this.accountFederationRepository.save(accountFederationEntity);

            try (LoggingContext logging = log(accountId, Map.of("type", "account.federation.add", "issuer", issuer, "id_at_issuer", idAtIssuer))) {
                logging.log("Added new login provider");
            }
        } else {
            accountEntity = optionalAccountEntity.get();
        }

        return Account.fromEntity(accountEntity);
    }

    @Override
    public List<AccountFederationWithSessions> getAccountFederationsWithSessions(UUID accountId) {
        final List<AccountFederationEntity> federationEntities = this.accountFederationRepository.findAllByAccountId(accountId);
        final Map<Pair<String, String>, List<AccountFederationSessionEntity>> federationSessionEntities = this.accountFederationSessionRepository.findAllByAccountId(accountId).stream()
                .collect(Collectors.groupingBy((v) -> new Pair<>(v.issuer(), v.idAtIssuer())));

        final List<AccountFederationWithSessions> result = new ArrayList<>(federationEntities.size());

        for (AccountFederationEntity federationEntity : federationEntities) {
            result.add(new AccountFederationWithSessions(
                    AccountFederation.fromEntity(federationEntity),
                    federationSessionEntities.getOrDefault(new Pair<>(federationEntity.issuer(), federationEntity.idAtIssuer()), List.of()).stream()
                            .map(AccountFederationSession::fromEntity)
                            .collect(Collectors.toList())
            ));
        }

        return result;
    }

    @Override
    public LoggingContext log(UUID accountId, Map<String, ?> fields) {
        return new RootLoggingContext(accountId, fields);
    }

    @Override
    @Transactional
    public boolean deleteAccountFederation(UUID accountId, String issuer, String idAtIssuer) {
        final int federationCount = this.accountFederationRepository.countByAccountId(accountId);

        // at least one federation has to be kept, otherwise the user could not login anymore
        if (federationCount < 2) {
            throw new AccountServiceException("Can't delete the last federation of an account", HttpStatus.NOT_ACCEPTABLE);
        }

        return this.accountFederationRepository.deleteByAccountIdAndIssuerAndIdAtIssuer(accountId, issuer, idAtIssuer);
    }

    @Override
    public boolean deleteSession(UUID accountId, String sessionId) {
        return this.accountFederationSessionRepository.deleteByAccountIdAndId(accountId, sessionId);
    }

    @Override
    @Transactional
    public boolean deleteAccount(UUID accountId) {
        this.accountRepository.deleteById(accountId);
        LOG.info("the account {} has been deleted", accountId);
        return true;
    }

    @Transactional
    public AccountEntity getOrCreateAccountInternal(String issuer, String idAtIssuer) {
        final Optional<AccountEntity> optionalAccount = this.accountRepository.findByFederation(issuer, idAtIssuer);
        AccountEntity accountEntity;

        if (optionalAccount.isEmpty()) {
            accountEntity = this.accountRepository.save(new AccountEntity(UUID.randomUUID(), this.clock.instant()));

            AccountFederationEntity accountFederationEntity = new AccountFederationEntity(issuer, idAtIssuer, accountEntity.id());
            accountFederationEntity = this.accountFederationRepository.save(accountFederationEntity);

            try (LoggingContext logging = log(accountEntity.id(), Map.of("type", "account.create", "issuer", issuer, "id_at_issuer", idAtIssuer))) {
                logging.logPersistent("Your account was created!");
            }
        } else {
            accountEntity = optionalAccount.get();
        }

        return accountEntity;
    }

    @Scheduled(fixedRate = 90L, timeUnit = TimeUnit.MINUTES)
    public void deleteAllExpiredSessions() {
        final int deleted = this.accountFederationSessionRepository.deleteAllExpired(this.clock.instant());
        LOG.info("scheduled deletion of expired sessions deleted {} rows", deleted);
    }

    private static abstract class AbstractLoggingContext implements LoggingContext {

        protected final Map<String, ?> fields;

        protected AbstractLoggingContext(Map<String, ?> fields) {
            this.fields = fields;
        }

        @Override
        public final LoggingContext with(Map<String, ?> fields) {
            return new ChildLoggingContext(this, fields);
        }
    }

    private static final class RootLoggingContext extends AbstractLoggingContext {

        private final UUID accountId;

        private RootLoggingContext(UUID accountId, Map<String, ?> fields) {
            super(fields);
            this.accountId = accountId;
        }

        @Override
        public void log(String message, Map<String, ?> fields) {
            logInternal(message, fields, false);
        }

        @Override
        public void logPersistent(String message, Map<String, ?> fields) {
            logInternal(message, fields, true);
        }

        private void logInternal(String message, Map<String, ?> fields, boolean persistent) {
            final Map<String, Object> combinedFields = new HashMap<>();
            combinedFields.putAll(this.fields);
            combinedFields.putAll(fields);

            final JSONObject fieldsJson = new JSONObject(combinedFields);
            LOG.info("account log; account_id={} fields={} persistent={}; {}", this.accountId, fieldsJson, persistent, message);
        }

        @Override
        public void close() {

        }
    }

    private static final class ChildLoggingContext extends AbstractLoggingContext {

        private final LoggingContext parent;

        private ChildLoggingContext(LoggingContext parent, Map<String, ?> fields) {
            super(fields);
            this.parent = parent;
        }

        @Override
        public void log(String message, Map<String, ?> fields) {
            logInternal(message, fields, false);
        }

        @Override
        public void logPersistent(String message, Map<String, ?> fields) {
            logInternal(message, fields, true);
        }

        private void logInternal(String message, Map<String, ?> fields, boolean persistent) {
            final Map<String, Object> combinedFields = new HashMap<>();
            combinedFields.putAll(this.fields);
            combinedFields.putAll(fields);

            if (persistent) {
                this.parent.logPersistent(message, combinedFields);
            } else {
                this.parent.log(message, combinedFields);
            }
        }

        @Override
        public void close() {
            // no-op
        }
    }
}
