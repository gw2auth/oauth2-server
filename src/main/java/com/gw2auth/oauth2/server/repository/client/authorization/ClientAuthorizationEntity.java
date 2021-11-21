package com.gw2auth.oauth2.server.repository.client.authorization;

import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.Set;

@Table("client_authorizations")
public record ClientAuthorizationEntity(@Column("account_id") long accountId,
                                        @Column("id") String id,
                                        @Column("client_registration_id") long clientRegistrationId,
                                        @Column("creation_time") Instant creationTime,
                                        @Column("last_update_time") Instant lastUpdateTime,
                                        @Column("display_name") String displayName,
                                        @Column("authorization_grant_type") String authorizationGrantType,
                                        @Column("authorized_scopes") Set<String> authorizedScopes,
                                        @Column("attributes") String attributes,
                                        @Column("state") String state,
                                        @Column("authorization_code_value") String authorizationCodeValue,
                                        @Column("authorization_code_issued_at") Instant authorizationCodeIssuedAt,
                                        @Column("authorization_code_expires_at") Instant authorizationCodeExpiresAt,
                                        @Column("authorization_code_metadata") String authorizationCodeMetadata,
                                        @Column("access_token_value") String accessTokenValue,
                                        @Column("access_token_issued_at") Instant accessTokenIssuedAt,
                                        @Column("access_token_expires_at") Instant accessTokenExpiresAt,
                                        @Column("access_token_metadata") String accessTokenMetadata,
                                        @Column("access_token_type") String accessTokenType,
                                        @Column("access_token_scopes") Set<String> accessTokenScopes,
                                        @Column("refresh_token_value") String refreshTokenValue,
                                        @Column("refresh_token_issued_at") Instant refreshTokenIssuedAt,
                                        @Column("refresh_token_expires_at") Instant refreshTokenExpiresAt,
                                        @Column("refresh_token_metadata") String refreshTokenMetadata) {
}
