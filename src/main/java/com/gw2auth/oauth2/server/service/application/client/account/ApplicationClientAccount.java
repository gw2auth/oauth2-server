package com.gw2auth.oauth2.server.service.application.client.account;

import com.gw2auth.oauth2.server.repository.application.client.account.ApplicationClientAccountEntity;

import java.util.Set;
import java.util.UUID;

public record ApplicationClientAccount(UUID applicationClientId,
                                       UUID accountId,
                                       UUID applicationId,
                                       ApprovalStatus approvalStatus,
                                       String approvalRequestMessage,
                                       Set<String> authorizedScopes) {

    public static ApplicationClientAccount fromEntity(ApplicationClientAccountEntity entity) {
        return new ApplicationClientAccount(
                entity.applicationClientId(),
                entity.accountId(),
                entity.applicationId(),
                ApprovalStatus.valueOf(entity.approvalStatus()),
                entity.approvalRequestMessage(),
                entity.authorizedScopes()
        );
    }

    public enum ApprovalStatus {
        PENDING,
        APPROVED
    }
}
