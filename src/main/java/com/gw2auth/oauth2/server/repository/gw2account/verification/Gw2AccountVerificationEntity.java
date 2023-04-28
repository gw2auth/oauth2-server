package com.gw2auth.oauth2.server.repository.gw2account.verification;

import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.util.UUID;

@Table("gw2_account_verifications")
public record Gw2AccountVerificationEntity(@Column("gw2_account_id") UUID gw2AccountId,
                                           @Column("account_id") UUID accountId) {
}
