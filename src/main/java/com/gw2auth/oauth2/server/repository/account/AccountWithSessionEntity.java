package com.gw2auth.oauth2.server.repository.account;

import org.springframework.data.relational.core.mapping.Embedded;

public record AccountWithSessionEntity(@Embedded.Empty(prefix = "acc_") AccountEntity account,
                                       @Embedded.Empty(prefix = "sess_") AccountFederationSessionEntity session) {
}
