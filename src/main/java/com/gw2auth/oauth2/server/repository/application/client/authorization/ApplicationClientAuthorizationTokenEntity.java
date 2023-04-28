package com.gw2auth.oauth2.server.repository.application.client.authorization;

import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.util.UUID;

@Table("application_client_authorization_gw2_accounts")
public record ApplicationClientAuthorizationTokenEntity(@Column("application_client_authorization_id") String applicationClientAuthorizationId,
                                                        @Column("account_id") UUID accountId,
                                                        @Column("gw2_account_id") UUID gw2AccountId) {
}
