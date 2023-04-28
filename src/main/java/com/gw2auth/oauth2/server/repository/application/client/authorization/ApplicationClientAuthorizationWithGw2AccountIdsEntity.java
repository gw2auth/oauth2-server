package com.gw2auth.oauth2.server.repository.application.client.authorization;

import org.springframework.data.relational.core.mapping.Column;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

public class ApplicationClientAuthorizationWithGw2AccountIdsEntity extends ApplicationClientAuthorizationEntity {

    @Column("gw2_account_ids")
    private final Set<UUID> gw2AccountIds;

    public ApplicationClientAuthorizationWithGw2AccountIdsEntity(String id, UUID accountId, UUID applicationClientId, Instant creationTime, Instant lastUpdateTime, String displayName, String authorizationGrantType, Set<String> authorizedScopes, String attributes, String state, String authorizationCodeValue, Instant authorizationCodeIssuedAt, Instant authorizationCodeExpiresAt, String authorizationCodeMetadata, String accessTokenValue, Instant accessTokenIssuedAt, Instant accessTokenExpiresAt, String accessTokenMetadata, String accessTokenType, Set<String> accessTokenScopes, String refreshTokenValue, Instant refreshTokenIssuedAt, Instant refreshTokenExpiresAt, String refreshTokenMetadata, Set<UUID> gw2AccountIds) {
        super(id, accountId, applicationClientId, creationTime, lastUpdateTime, displayName, authorizationGrantType, authorizedScopes, attributes, state, authorizationCodeValue, authorizationCodeIssuedAt, authorizationCodeExpiresAt, authorizationCodeMetadata, accessTokenValue, accessTokenIssuedAt, accessTokenExpiresAt, accessTokenMetadata, accessTokenType, accessTokenScopes, refreshTokenValue, refreshTokenIssuedAt, refreshTokenExpiresAt, refreshTokenMetadata);
        this.gw2AccountIds = gw2AccountIds;
    }

    @Column("gw2_account_ids")
    public Set<UUID> gw2AccountIds() {
        return this.gw2AccountIds;
    }
}
