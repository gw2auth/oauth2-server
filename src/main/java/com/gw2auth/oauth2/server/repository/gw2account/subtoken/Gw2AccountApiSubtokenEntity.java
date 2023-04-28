package com.gw2auth.oauth2.server.repository.gw2account.subtoken;

import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Table("gw2_account_api_subtokens")
public record Gw2AccountApiSubtokenEntity(@Column("account_id") UUID accountId,
                                          @Column("gw2_account_id") UUID gw2AccountId,
                                          @Column("gw2_api_permissions_bit_set") int gw2ApiPermissionsBitSet,
                                          @Column("gw2_api_subtoken") String gw2ApiSubtoken,
                                          @Column("expiration_time") Instant expirationTime) {
}
