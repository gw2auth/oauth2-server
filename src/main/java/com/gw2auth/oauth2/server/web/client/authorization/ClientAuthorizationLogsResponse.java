package com.gw2auth.oauth2.server.web.client.authorization;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationLogEntity;

import java.time.Instant;
import java.util.List;

public record ClientAuthorizationLogsResponse(@JsonProperty("page") int page,
                                              @JsonProperty("nextPage") int nextPage,
                                              @JsonProperty("logs") List<Log> logs) {

    public record Log(@JsonProperty("timestamp") Instant timestamp, @JsonProperty("messages") List<String> messages) {

        public static Log create(ClientAuthorizationLogEntity entity) {
            return new Log(entity.timestamp(), entity.messages());
        }
    }
}
