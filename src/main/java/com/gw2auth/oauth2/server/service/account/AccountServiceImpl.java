package com.gw2auth.oauth2.server.service.account;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gw2auth.oauth2.server.repository.account.*;
import com.gw2auth.oauth2.server.service.Clocked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Service
@EnableScheduling
public class AccountServiceImpl implements AccountService, Clocked {

    private static final Logger LOG = LoggerFactory.getLogger(AccountServiceImpl.class);

    private final AccountRepository accountRepository;
    private final AccountFederationRepository accountFederationRepository;
    private final AccountFederationSessionRepository accountFederationSessionRepository;
    private final S3Client s3;
    private final String bucket;
    private final String prefix;
    private final ObjectMapper mapper;
    private Clock clock;

    @Autowired
    public AccountServiceImpl(AccountRepository accountRepository,
                              AccountFederationRepository accountFederationRepository,
                              AccountFederationSessionRepository accountFederationSessionRepository,
                              @Qualifier("oauth2-add-federation-s3-client") S3Client s3,
                              @Value("${com.gw2auth.oauth2.addfederation.s3.bucket}") String bucket,
                              @Value("${com.gw2auth.oauth2.addfederation.s3.prefix}") String prefix,
                              ObjectMapper mapper) {

        this.accountRepository = accountRepository;
        this.accountFederationRepository = accountFederationRepository;
        this.accountFederationSessionRepository = accountFederationSessionRepository;
        this.s3 = s3;
        this.bucket = bucket;
        this.prefix = prefix;
        this.mapper = mapper;
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
    public AccountFederationSession createNewSession(String issuer, String idAtIssuer, byte[] metadata) {
        final Instant now = this.clock.instant();
        final byte[] sessionIdBytes = new byte[64];
        new SecureRandom().nextBytes(sessionIdBytes);

        final AccountFederationSessionEntity entity = this.accountFederationSessionRepository.save(new AccountFederationSessionEntity(
                Base64.getUrlEncoder().withoutPadding().encodeToString(sessionIdBytes),
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
        final PutObjectRequest s3Request = PutObjectRequest.builder()
                .bucket(this.bucket)
                .key(this.prefix + accountId)
                .build();

        this.s3.putObject(s3Request, RequestBody.fromString(issuer, StandardCharsets.UTF_8));
    }

    @Override
    public boolean checkAndDeletePrepareAddFederation(UUID accountId, String issuer) {
        final GetObjectRequest s3Request = GetObjectRequest.builder()
                .bucket(this.bucket)
                .key(this.prefix + accountId)
                .build();

        try (ResponseInputStream<GetObjectResponse> s3Object = this.s3.getObject(s3Request)) {
            this.s3.deleteObject(
                    DeleteObjectRequest.builder()
                            .bucket(this.bucket)
                            .key(this.prefix + accountId)
                            .build()
            );

            return new String(s3Object.readAllBytes(), StandardCharsets.UTF_8).equals(issuer);
        } catch (AwsServiceException | IOException e) {
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
    public LoggingContext log(UUID accountId, Map<String, ?> fields) {
        return new RootLoggingContext(this.mapper, accountId, fields);
    }

    @Override
    public boolean deleteSession(UUID accountId, String sessionId) {
        return this.accountFederationSessionRepository.deleteByAccountIdAndId(accountId, sessionId);
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

        private final ObjectMapper mapper;
        private final UUID accountId;

        private RootLoggingContext(ObjectMapper mapper, UUID accountId, Map<String, ?> fields) {
            super(fields);
            this.mapper = mapper;
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

            final List<MDC.MDCCloseable> mdcCloseables = new ArrayList<>();
            for (Map.Entry<String, ?> entry : combinedFields.entrySet()) {
                final JsonNode node = this.mapper.valueToTree(entry.getValue());
                final String value;
                if (node.isTextual()) {
                    value = node.textValue();
                } else {
                    try {
                        value = this.mapper.writeValueAsString(node);
                    } catch (JsonProcessingException e) {
                        throw new RuntimeException(e);
                    }
                }

                mdcCloseables.add(MDC.putCloseable(entry.getKey(), value));
            }

            try (MDC.MDCCloseable mdc = MDC.putCloseable("account_id", this.accountId.toString())) {
                try (ComposedMDCCloseable unused = new ComposedMDCCloseable(mdcCloseables)) {
                    LOG.info("account log; {}", message);
                }
            }
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

    private static final class ComposedMDCCloseable implements AutoCloseable {

        private final Iterable<MDC.MDCCloseable> mdcCloseables;

        private ComposedMDCCloseable(Iterable<MDC.MDCCloseable> mdcCloseables) {
            this.mdcCloseables = mdcCloseables;
        }

        @Override
        public void close() {
            RuntimeException first = null;

            for (MDC.MDCCloseable mdcCloseable : this.mdcCloseables) {
                try {
                    mdcCloseable.close();
                } catch (Exception e) {
                    first = wrap(first, e);
                }
            }

            if (first != null) {
                throw first;
            }
        }

        private static RuntimeException wrap(RuntimeException first, Exception curr) {
            if (first == null) {
                return new RuntimeException(curr);
            }

            first.addSuppressed(curr);
            return first;
        }
    }
}
