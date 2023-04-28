package com.gw2auth.oauth2.server.repository.application.account;

import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.util.UUID;

@Table("application_account_subs")
public record ApplicationAccountSubEntity(@Column("application_id") UUID applicationId,
                                          @Column("account_id") UUID accountId,
                                          @Column("account_sub") UUID accountSub) {
}
