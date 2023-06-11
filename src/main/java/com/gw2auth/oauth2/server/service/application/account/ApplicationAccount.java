package com.gw2auth.oauth2.server.service.application.account;

import com.gw2auth.oauth2.server.repository.application.account.ApplicationAccountWithSubEntity;

import java.time.Instant;
import java.util.UUID;

public record ApplicationAccount(UUID applicationId,
                                 UUID accountId,
                                 Instant creationTime,
                                 UUID accountSub) {

    public static ApplicationAccount fromEntity(ApplicationAccountWithSubEntity entity) {
        return new ApplicationAccount(
                entity.account().applicationId(),
                entity.account().accountId(),
                entity.account().creationTime(),
                entity.accountSub()
        );
    }
}
