package com.gw2auth.oauth2.server.repository.application.account;

import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Table("application_accounts")
public record ApplicationAccountEntity(@Column("application_id") UUID applicationId,
                                      @Column("account_id") UUID accountId,
                                      @Column("creation_time") Instant creationTime) {

}
