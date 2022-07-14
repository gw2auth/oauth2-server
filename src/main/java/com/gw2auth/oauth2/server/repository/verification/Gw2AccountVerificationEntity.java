package com.gw2auth.oauth2.server.repository.verification;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.util.UUID;

@Table("gw2_account_verifications")
public record Gw2AccountVerificationEntity(@Id @Column("gw2_account_id") UUID gw2AccountId,
                                           @Column("account_id") UUID accountId) {

    public Gw2AccountVerificationEntity withAccountId(UUID accountId) {
        return new Gw2AccountVerificationEntity(this.gw2AccountId, accountId);
    }
}
