package com.gw2auth.oauth2.server.repository.client.authorization;

import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.util.UUID;

@Table("client_authorization_tokens")
public record ClientAuthorizationTokenEntity(@Column("client_authorization_id") String clientAuthorizationId,
                                             @Column("account_id") UUID accountId,
                                             @Column("gw2_account_id") UUID gw2AccountId) {
}
