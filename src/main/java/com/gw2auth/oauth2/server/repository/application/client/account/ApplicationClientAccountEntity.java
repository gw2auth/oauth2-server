package com.gw2auth.oauth2.server.repository.application.client.account;

import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.util.Set;
import java.util.UUID;

@Table("application_client_accounts")
public record ApplicationClientAccountEntity(@Column("application_client_id") UUID applicationClientId,
                                             @Column("account_id") UUID accountId,
                                             @Column("application_id") UUID applicationId,
                                             @Column("approval_status") String approvalStatus,
                                             @Column("approval_request_message") String approvalRequestMessage,
                                             @Column("authorized_scopes") Set<String> authorizedScopes) {

}
