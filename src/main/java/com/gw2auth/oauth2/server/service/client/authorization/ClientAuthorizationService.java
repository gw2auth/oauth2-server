package com.gw2auth.oauth2.server.service.client.authorization;

import java.io.Closeable;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public interface ClientAuthorizationService {

    List<ClientAuthorization> getClientAuthorizations(long accountId);

    List<ClientAuthorization> getClientAuthorizations(long accountId, Set<String> gw2AccountIds);

    Optional<ClientAuthorization> getClientAuthorization(long accountId, long clientRegistrationId);

    void createEmptyClientAuthorizationIfNotExists(long accountId, long clientRegistrationId);

    void deleteClientAuthorization(long accountId, String clientId);

    void deleteClientAuthorization(long accountId, long clientRegistrationId);

    void updateTokens(long accountId, long clientRegistrationId, Map<String, ClientAuthorization.Token> tokens);

    LoggingContext log(long accountId, long clientRegistrationId);

    interface LoggingContext extends Closeable {

        void log(String message);

        default void log(String fmt, Object... args) {
            log(String.format(fmt, args));
        }

        @Override
        void close();
    }
}
