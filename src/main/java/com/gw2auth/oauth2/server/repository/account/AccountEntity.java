package com.gw2auth.oauth2.server.repository.account;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

@Table("accounts")
public record AccountEntity(@Id Long id,
                            @Column("creation_time") Instant creationTime) {
}
