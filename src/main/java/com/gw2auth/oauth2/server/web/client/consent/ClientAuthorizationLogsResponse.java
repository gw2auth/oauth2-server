package com.gw2auth.oauth2.server.web.client.consent;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.repository.client.consent.ClientConsentLogEntity;

import java.time.Instant;
import java.util.List;

public record ClientAuthorizationLogsResponse(@JsonProperty("page") int page,
                                              @JsonProperty("nextPage") int nextPage,
                                              @JsonProperty("logs") List<Log> logs) {

    public record Log(@JsonProperty("timestamp") Instant timestamp, @JsonProperty("type") String type, @JsonProperty("messages") List<String> messages) {

        public static Log create(ClientConsentLogEntity entity) {
            return new Log(entity.timestamp(), entity.type(), entity.messages());
        }
    }
}
