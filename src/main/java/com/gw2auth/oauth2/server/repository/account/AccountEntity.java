package com.gw2auth.oauth2.server.repository.account;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Table("accounts")
public record AccountEntity(@Id @Column("id") UUID id,
                            @Column("creation_time") Instant creationTime) {
}
