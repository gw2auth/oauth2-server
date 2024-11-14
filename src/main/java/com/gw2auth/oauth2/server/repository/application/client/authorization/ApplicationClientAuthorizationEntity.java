package com.gw2auth.oauth2.server.repository.application.client.authorization;

import org.jspecify.annotations.Nullable;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Table("application_client_authorizations")
public record ApplicationClientAuthorizationEntity(@Column("id") String id,
                                                   @Column("account_id") UUID accountId,
                                                   @Column("application_client_id") UUID applicationClientId,
                                                   @Column("creation_time") Instant creationTime,
                                                   @Column("last_update_time") Instant lastUpdateTime,
                                                   @Column("display_name") String displayName,
                                                   @Column("authorization_grant_type") String authorizationGrantType,
                                                   @Column("authorized_scopes") Set<String> authorizedScopes,
                                                   @Column("attributes") @Nullable String attributes,
                                                   @Column("state") @Nullable String state,
                                                   @Column("authorization_code_value") @Nullable String authorizationCodeValue,
                                                   @Column("authorization_code_issued_at") @Nullable Instant authorizationCodeIssuedAt,
                                                   @Column("authorization_code_expires_at") @Nullable Instant authorizationCodeExpiresAt,
                                                   @Column("authorization_code_metadata") @Nullable String authorizationCodeMetadata,
                                                   @Column("access_token_value") @Nullable String accessTokenValue,
                                                   @Column("access_token_issued_at") @Nullable Instant accessTokenIssuedAt,
                                                   @Column("access_token_expires_at") @Nullable Instant accessTokenExpiresAt,
                                                   @Column("access_token_metadata") @Nullable String accessTokenMetadata,
                                                   @Column("access_token_type") @Nullable String accessTokenType,
                                                   @Column("access_token_scopes") Set<String> accessTokenScopes,
                                                   @Column("refresh_token_value") @Nullable String refreshTokenValue,
                                                   @Column("refresh_token_issued_at") @Nullable Instant refreshTokenIssuedAt,
                                                   @Column("refresh_token_expires_at") @Nullable Instant refreshTokenExpiresAt,
                                                   @Column("refresh_token_metadata") @Nullable String refreshTokenMetadata) {

}
