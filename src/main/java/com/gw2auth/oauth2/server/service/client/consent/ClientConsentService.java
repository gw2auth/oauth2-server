package com.gw2auth.oauth2.server.service.client.consent;

import java.io.Closeable;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface ClientConsentService {

    String GW2AUTH_VERIFIED_SCOPE = "gw2auth:verified";

    List<ClientConsent> getClientConsents(UUID accountId);

    Optional<ClientConsent> getClientConsent(UUID accountId, UUID clientRegistrationId);

    void createEmptyClientConsentIfNotExists(UUID accountId, UUID clientRegistrationId);

    void deleteClientConsent(UUID accountId, UUID clientRegistrationId);

    LoggingContext log(UUID accountId, UUID clientRegistrationId, LogType logType);

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
