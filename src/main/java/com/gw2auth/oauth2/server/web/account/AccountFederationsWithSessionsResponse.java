package com.gw2auth.oauth2.server.web.account;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public record AccountFederationsWithSessionsResponse(@JsonProperty("currentIssuer") String currentIssuer,
                                                     @JsonProperty("currentIdAtIssuer") String currentIdAtIssuer,
                                                     @JsonProperty("currentSessionId") String currentSessionId,
                                                     @JsonProperty("federations") List<AccountFederationWithSessionsResponse> federations) {
}
