package com.gw2auth.oauth2.server.web.account;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public record AccountSessionsResponse(@JsonProperty("currentAccountSessionId") String currentAccountSessionId,
                                      @JsonProperty("accountSessions") List<AccountSessionResponse> accountSessions) {
}
