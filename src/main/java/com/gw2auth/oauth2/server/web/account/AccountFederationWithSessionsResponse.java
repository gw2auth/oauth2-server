package com.gw2auth.oauth2.server.web.account;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.account.AccountFederationSession;
import com.gw2auth.oauth2.server.service.account.AccountFederationWithSessions;

import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Collectors;

public record AccountFederationWithSessionsResponse(@JsonProperty("issuer") String issuer,
                                                    @JsonProperty("idAtIssuer") String idAtIssuer,
                                                    @JsonProperty("sessions") List<Session> sessions) {

    public static AccountFederationWithSessionsResponse create(AccountFederationWithSessions value) {
        return new AccountFederationWithSessionsResponse(
                value.federation().issuer(),
                value.federation().idAtIssuer(),
                value.sessions().stream()
                        .sorted(Comparator.comparing(AccountFederationSession::creationTime))
                        .map(Session::create)
                        .collect(Collectors.toList())
        );
    }

    public record Session(@JsonProperty("id") String id, @JsonProperty("creationTime") Instant creationTime, @JsonProperty("expirationTime") Instant expirationTime) {

        public static Session create(AccountFederationSession value) {
            return new Session(value.id(), value.creationTime(), value.expirationTime());
        }
    }
}
