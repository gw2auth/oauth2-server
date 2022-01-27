package com.gw2auth.oauth2.server.repository.apitoken;

import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Table("gw2_api_tokens")
public record ApiTokenEntity(@Column("account_id") long accountId,
                             @Column("gw2_account_id") UUID gw2AccountId,
                             @Column("creation_time") Instant creationTime,
                             @Column("gw2_api_token") String gw2ApiToken,
                             @Column("gw2_api_permissions") Set<String> gw2ApiPermissions,
                             @Column("display_name") String displayName) {

    public ApiTokenEntity withGw2ApiToken(String gw2ApiToken) {
        return new ApiTokenEntity(this.accountId, this.gw2AccountId, this.creationTime, gw2ApiToken, this.gw2ApiPermissions, this.displayName);
    }

    public ApiTokenEntity withGw2ApiPermissions(Set<String> gw2ApiPermissions) {
        return new ApiTokenEntity(this.accountId, this.gw2AccountId, this.creationTime, this.gw2ApiToken, gw2ApiPermissions, this.displayName);
    }

    public ApiTokenEntity withDisplayName(String displayName) {
        return new ApiTokenEntity(this.accountId, this.gw2AccountId, this.creationTime, this.gw2ApiToken, this.gw2ApiPermissions, displayName);
    }
}
