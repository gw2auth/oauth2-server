package com.gw2auth.oauth2.server.repository.gw2account.apitoken;

import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Table("gw2_account_api_tokens")
public class Gw2AccountApiTokenEntity {
    @Column("account_id")
    private final UUID accountId;
    @Column("gw2_account_id")
    private final UUID gw2AccountId;
    @Column("creation_time")
    private final Instant creationTime;
    @Column("gw2_api_token")
    private final String gw2ApiToken;
    @Column("gw2_api_permissions_bit_set")
    private final int gw2ApiPermissionsBitSet;
    @Column("last_valid_time")
    private final Instant lastValidTime;
    @Column("last_valid_check_time")
    private final Instant lastValidCheckTime;

    public Gw2AccountApiTokenEntity(UUID accountId,
                                    UUID gw2AccountId,
                                    Instant creationTime,
                                    String gw2ApiToken,
                                    int gw2ApiPermissionsBitSet,
                                    Instant lastValidTime,
                                    Instant lastValidCheckTime) {
        this.accountId = accountId;
        this.gw2AccountId = gw2AccountId;
        this.creationTime = creationTime;
        this.gw2ApiToken = gw2ApiToken;
        this.gw2ApiPermissionsBitSet = gw2ApiPermissionsBitSet;
        this.lastValidTime = lastValidTime;
        this.lastValidCheckTime = lastValidCheckTime;
    }

    @Column("account_id")
    public UUID accountId() {
        return this.accountId;
    }

    @Column("gw2_account_id")
    public UUID gw2AccountId() {
        return this.gw2AccountId;
    }

    @Column("creation_time")
    public Instant creationTime() {
        return this.creationTime;
    }

    @Column("gw2_api_token")
    public String gw2ApiToken() {
        return this.gw2ApiToken;
    }

    @Column("gw2_api_permissions_bit_set")
    public int gw2ApiPermissionsBitSet() {
        return this.gw2ApiPermissionsBitSet;
    }

    @Column("last_valid_time")
    public Instant lastValidTime() {
        return this.lastValidTime;
    }

    @Column("last_valid_check_time")
    public Instant lastValidCheckTime() {
        return this.lastValidCheckTime;
    }
}
