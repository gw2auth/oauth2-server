package com.gw2auth.oauth2.server.repository.summary;

import org.springframework.data.relational.core.mapping.Column;

public record ApplicationSummaryEntity(@Column("accounts") long accounts,
                                       @Column("api_tokens") long apiTokens,
                                       @Column("verified_gw2_accounts") long verifiedGw2Accounts,
                                       @Column("client_registrations") long clientRegistrations,
                                       @Column("client_authorizations") long clientAuthorizations) {
}
