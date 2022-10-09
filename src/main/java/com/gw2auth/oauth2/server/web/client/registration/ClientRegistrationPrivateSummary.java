package com.gw2auth.oauth2.server.web.client.registration;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.summary.ClientSummary;

public record ClientRegistrationPrivateSummary(@JsonProperty("accounts") long accounts,
                                               @JsonProperty("gw2Accounts") long gw2Accounts,
                                               @JsonProperty("authPast1d") long authPast1d,
                                               @JsonProperty("authPast3d") long authPast3d,
                                               @JsonProperty("authPast7d") long authPast7d,
                                               @JsonProperty("authPast30d") long authPast30d) {

    public static ClientRegistrationPrivateSummary create(ClientSummary clientSummary) {
        return new ClientRegistrationPrivateSummary(
                clientSummary.accounts(),
                clientSummary.gw2Accounts(),
                clientSummary.authPast1d(),
                clientSummary.authPast3d(),
                clientSummary.authPast7d(),
                clientSummary.authPast30d()
        );
    }
}
