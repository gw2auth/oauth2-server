package com.gw2auth.oauth2.server.repository.client.authorization;

import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

@Table("client_authorization_tokens")
public record ClientAuthorizationTokenEntity(@Column("account_id") long accountId,
                                             @Column("client_registration_id") long clientRegistrationId,
                                             @Column("gw2_account_id") String gw2AccountId,
                                             @Column("gw2_api_subtoken") String gw2ApiSubtoken,
                                             @Column("expiration_time") Instant expirationTime) {
}
