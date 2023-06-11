package com.gw2auth.oauth2.server.repository.gw2account.apitoken;

import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Table("gw2_account_api_tokens")
public record Gw2AccountApiTokenEntity(@Column("account_id") UUID accountId,
                                       @Column("gw2_account_id") UUID gw2AccountId,
                                       @Column("creation_time") Instant creationTime,
                                       @Column("gw2_api_token") String gw2ApiToken,
                                       @Column("gw2_api_permissions_bit_set") int gw2ApiPermissionsBitSet,
                                       @Column("last_valid_time") Instant lastValidTime,
                                       @Column("last_valid_check_time") Instant lastValidCheckTime) {

}
