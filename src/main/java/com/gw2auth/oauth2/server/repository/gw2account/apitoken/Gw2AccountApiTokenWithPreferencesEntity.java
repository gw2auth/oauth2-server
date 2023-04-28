package com.gw2auth.oauth2.server.repository.gw2account.apitoken;

import org.springframework.data.relational.core.mapping.Column;

import java.time.Instant;
import java.util.UUID;

public class Gw2AccountApiTokenWithPreferencesEntity extends Gw2AccountApiTokenEntity {

    @Column("display_name")
    private final String displayName;

    @Column("order_rank")
    private final String orderRank;

    public Gw2AccountApiTokenWithPreferencesEntity(UUID accountId, UUID gw2AccountId, Instant creationTime, String gw2ApiToken, int gw2ApiPermissionsBitSet, Instant lastValidTime, Instant lastValidCheckTime, String displayName, String orderRank) {
        super(accountId, gw2AccountId, creationTime, gw2ApiToken, gw2ApiPermissionsBitSet, lastValidTime, lastValidCheckTime);
        this.displayName = displayName;
        this.orderRank = orderRank;
    }

    public String displayName() {
        return this.displayName;
    }

    public String orderRank() {
        return this.orderRank;
    }
}
