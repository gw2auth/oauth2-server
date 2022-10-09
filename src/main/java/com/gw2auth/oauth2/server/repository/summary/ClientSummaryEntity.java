package com.gw2auth.oauth2.server.repository.summary;

import org.springframework.data.relational.core.mapping.Column;

public record ClientSummaryEntity(@Column("accounts") long accounts,
                                  @Column("gw2_accounts") long gw2Accounts,
                                  @Column("authorizations_past_1d") long authPast1d,
                                  @Column("authorizations_past_3d") long authPast3d,
                                  @Column("authorizations_past_7d") long authPast7d,
                                  @Column("authorizations_past_30d") long authPast30d) {
}
