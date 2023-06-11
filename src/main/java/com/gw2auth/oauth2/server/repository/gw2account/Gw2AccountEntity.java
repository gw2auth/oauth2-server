package com.gw2auth.oauth2.server.repository.gw2account;

import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Table("gw2_accounts")
public record Gw2AccountEntity(@Column("account_id") UUID accountId,
                               @Column("gw2_account_id") UUID gw2AccountId,
                               @Column("gw2_account_name") String gw2AccountName,
                               @Column("creation_time") Instant creationTime,
                               @Column("display_name") String displayName,
                               @Column("order_rank") String orderRank) {

}
