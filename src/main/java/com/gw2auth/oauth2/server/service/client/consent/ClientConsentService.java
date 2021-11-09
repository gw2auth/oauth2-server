package com.gw2auth.oauth2.server.service.client.consent;

import java.io.Closeable;
import java.util.List;
import java.util.Optional;

public interface ClientConsentService {

    String GW2AUTH_VERIFIED_SCOPE = "gw2auth:verified";

    List<ClientConsent> getClientConsents(long accountId);

    Optional<ClientConsent> getClientConsent(long accountId, long clientRegistrationId);

    void createEmptyClientConsentIfNotExists(long accountId, long clientRegistrationId);

    void deleteClientConsent(long accountId, String clientId);

    void deleteClientConsent(long accountId, long clientRegistrationId);

    LoggingContext log(long accountId, long clientRegistrationId, LogType logType);

    enum LogType {

        CONSENT,
        AUTHORIZATION,
        ACCESS_TOKEN
    }

    interface LoggingContext extends Closeable {

        void log(String message);

        default void log(String fmt, Object... args) {
            log(String.format(fmt, args));
        }

        @Override
        void close();
    }
}
