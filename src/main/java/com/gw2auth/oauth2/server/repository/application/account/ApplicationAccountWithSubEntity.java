package com.gw2auth.oauth2.server.repository.application.account;

import org.springframework.data.relational.core.mapping.Column;

import java.time.Instant;
import java.util.UUID;

public class ApplicationAccountWithSubEntity extends ApplicationAccountEntity {
    @Column("account_sub")
    private final UUID accountSub;

    public ApplicationAccountWithSubEntity(UUID applicationId,
                                           UUID accountId,
                                           Instant creationTime,
                                           UUID accountSub) {
        super(applicationId, accountId, creationTime);
        this.accountSub = accountSub;
    }

    public UUID accountSub() {
        return this.accountSub;
    }
}
