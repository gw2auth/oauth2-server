package com.gw2auth.oauth2.server.repository.application.account;

import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Table("application_accounts")
public class ApplicationAccountEntity {
    @Column("application_id")
    private final UUID applicationId;
    @Column("account_id")
    private final UUID accountId;
    @Column("creation_time")
    private final Instant creationTime;

    public ApplicationAccountEntity(UUID applicationId,
                                    UUID accountId,
                                    Instant creationTime) {
        this.applicationId = applicationId;
        this.accountId = accountId;
        this.creationTime = creationTime;
    }

    @Column("application_id")
    public UUID applicationId() {
        return applicationId;
    }

    @Column("account_id")
    public UUID accountId() {
        return accountId;
    }

    @Column("creation_time")
    public Instant creationTime() {
        return creationTime;
    }
}
