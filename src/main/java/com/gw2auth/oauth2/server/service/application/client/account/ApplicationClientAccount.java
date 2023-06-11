package com.gw2auth.oauth2.server.service.application.client.account;

import com.gw2auth.oauth2.server.repository.application.client.account.ApplicationClientAccountEntity;
import com.gw2auth.oauth2.server.service.OAuth2Scope;

import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public record ApplicationClientAccount(UUID applicationClientId,
                                       UUID accountId,
                                       UUID applicationId,
                                       ApprovalStatus approvalStatus,
                                       String approvalRequestMessage,
                                       Set<OAuth2Scope> authorizedScopes) {

    public static ApplicationClientAccount fromEntity(ApplicationClientAccountEntity entity) {
        return new ApplicationClientAccount(
                entity.applicationClientId(),
                entity.accountId(),
                entity.applicationId(),
                ApprovalStatus.valueOf(entity.approvalStatus()),
                entity.approvalRequestMessage(),
                entity.authorizedScopes().stream()
                        .map(OAuth2Scope::fromOAuth2Required)
                        .collect(Collectors.toUnmodifiableSet())
        );
    }

    public enum ApprovalStatus {
        PENDING,
        APPROVED
    }
}
