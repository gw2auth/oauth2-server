package com.gw2auth.oauth2.server.repository.account;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

@Table("account_federation_sessions")
public record AccountFederationSessionEntity(@Id @Column("id") String id,
                                             @Column("issuer") String issuer,
                                             @Column("id_at_issuer") String idAtIssuer,
                                             @Column("creation_time") Instant creationTime,
                                             @Column("expiration_time") Instant expirationTime) {
}
