package com.gw2auth.oauth2.server.repository.client.authorization;

import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

@Table("client_authorization_tokens")
public record ClientAuthorizationTokenEntity(@Column("account_id") long accountId,
                                             @Column("client_authorization_id") String clientAuthorizationId,
                                             @Column("gw2_account_id") String gw2AccountId) {
}
