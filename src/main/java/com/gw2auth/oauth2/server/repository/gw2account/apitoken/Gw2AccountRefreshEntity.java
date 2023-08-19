package com.gw2auth.oauth2.server.repository.gw2account.apitoken;

import org.springframework.data.relational.core.mapping.Column;

import java.util.UUID;

public record Gw2AccountRefreshEntity(@Column("account_id") UUID accountId,
                                      @Column("gw2_account_id") UUID gw2AccountId,
                                      @Column("gw2_account_name") String gw2AccountName,
                                      @Column("gw2_api_token") String gw2ApiToken) {
}
