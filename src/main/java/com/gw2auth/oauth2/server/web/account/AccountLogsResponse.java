package com.gw2auth.oauth2.server.web.account;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.account.AccountLog;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record AccountLogsResponse(@JsonProperty("page") int page,
                                  @JsonProperty("nextPage") int nextPage,
                                  @JsonProperty("logs") List<Log> logs) {

    public record Log(@JsonProperty("timestamp") Instant timestamp,
                      @JsonProperty("message") String message,
                      @JsonProperty("fields") Map<String, ?> fields) {

        public static Log create(AccountLog value) {
            return new Log(value.timestamp(), value.message(), value.fields());
        }
    }
}
