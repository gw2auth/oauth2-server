package com.gw2auth.oauth2.server.repository.application;

import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Table("applications")
public record ApplicationEntity(@Column("id") UUID id,
                                @Column("account_id") UUID accountId,
                                @Column("creation_time") Instant creationTime,
                                @Column("display_name") String displayName) {
}
