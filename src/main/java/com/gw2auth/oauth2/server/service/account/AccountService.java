package com.gw2auth.oauth2.server.service.account;

import java.io.Closeable;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public interface AccountService {

    Account getOrCreateAccount(String issuer, String idAtIssuer);

    AccountFederationSession createNewSession(String issuer, String idAtIssuer, byte[] metadata);

    AccountFederationSession updateSession(String sessionId, String issuer, String idAtIssuer, byte[] metadata);

    Optional<AccountSession> getAccountForSession(String sessionId);

    void prepareAddFederation(UUID accountId, String issuer);
    boolean checkAndDeletePrepareAddFederation(UUID accountId, String issuer);

    Account addAccountFederationOrReturnExisting(UUID accountId, String issuer, String idAtIssuer);

    default LoggingContext log(UUID accountId) {
        return log(accountId, Map.of());
    }

    LoggingContext log(UUID accountId, Map<String, ?> fields);

    default void log(UUID accountId, String message, Map<String, ?> fields) {
        try (LoggingContext ctx = log(accountId, fields)) {
            ctx.log(message);
        }
    }

    boolean deleteSession(UUID accountId, String sessionId);

    interface LoggingContext extends Closeable {

        LoggingContext with(Map<String, ?> fields);
        default void log(String message) {
            log(message, Map.of());
        }
        void log(String message, Map<String, ?> fields);
        default void logPersistent(String message) {
            logPersistent(message, Map.of());
        }
        void logPersistent(String message, Map<String, ?> fields);

        @Override
        void close();
    }
}
