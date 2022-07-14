package com.gw2auth.oauth2.server.repository.account;

import org.springframework.data.relational.core.mapping.Column;

import java.time.Instant;
import java.util.UUID;

public record AccountWithFederationEntity(@Column("id") UUID id,
                                          @Column("creation_time") Instant creationTime,
                                          @Column("issuer") String issuer,
                                          @Column("id_at_issuer") String idAtIssuer) {
}
