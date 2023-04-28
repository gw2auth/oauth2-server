package com.gw2auth.oauth2.server.repository.application.client.authorization;

import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Table("application_client_authorizations")
public class ApplicationClientAuthorizationEntity {
    @Column("id")
    private final String id;
    @Column("account_id")
    private final UUID accountId;
    @Column("application_client_id")
    private final UUID applicationClientId;
    @Column("creation_time")
    private final Instant creationTime;
    @Column("last_update_time")
    private final Instant lastUpdateTime;
    @Column("display_name")
    private final String displayName;
    @Column("authorization_grant_type")
    private final String authorizationGrantType;
    @Column("authorized_scopes")
    private final Set<String> authorizedScopes;
    @Column("attributes")
    private final String attributes;
    @Column("state")
    private final String state;
    @Column("authorization_code_value")
    private final String authorizationCodeValue;
    @Column("authorization_code_issued_at")
    private final Instant authorizationCodeIssuedAt;
    @Column("authorization_code_expires_at")
    private final Instant authorizationCodeExpiresAt;
    @Column("authorization_code_metadata")
    private final String authorizationCodeMetadata;
    @Column("access_token_value")
    private final String accessTokenValue;
    @Column("access_token_issued_at")
    private final Instant accessTokenIssuedAt;
    @Column("access_token_expires_at")
    private final Instant accessTokenExpiresAt;
    @Column("access_token_metadata")
    private final String accessTokenMetadata;
    @Column("access_token_type")
    private final String accessTokenType;
    @Column("access_token_scopes")
    private final Set<String> accessTokenScopes;
    @Column("refresh_token_value")
    private final String refreshTokenValue;
    @Column("refresh_token_issued_at")
    private final Instant refreshTokenIssuedAt;
    @Column("refresh_token_expires_at")
    private final Instant refreshTokenExpiresAt;
    @Column("refresh_token_metadata")
    private final String refreshTokenMetadata;

    public ApplicationClientAuthorizationEntity(String id,
                                                UUID accountId,
                                                UUID applicationClientId,
                                                Instant creationTime,
                                                Instant lastUpdateTime,
                                                String displayName,
                                                String authorizationGrantType,
                                                Set<String> authorizedScopes,
                                                String attributes,
                                                String state,
                                                String authorizationCodeValue,
                                                Instant authorizationCodeIssuedAt,
                                                Instant authorizationCodeExpiresAt,
                                                String authorizationCodeMetadata,
                                                String accessTokenValue,
                                                Instant accessTokenIssuedAt,
                                                Instant accessTokenExpiresAt,
                                                String accessTokenMetadata,
                                                String accessTokenType,
                                                Set<String> accessTokenScopes,
                                                String refreshTokenValue,
                                                Instant refreshTokenIssuedAt,
                                                Instant refreshTokenExpiresAt,
                                                String refreshTokenMetadata) {

        this.id = id;
        this.accountId = accountId;
        this.applicationClientId = applicationClientId;
        this.creationTime = creationTime;
        this.lastUpdateTime = lastUpdateTime;
        this.displayName = displayName;
        this.authorizationGrantType = authorizationGrantType;
        this.authorizedScopes = authorizedScopes;
        this.attributes = attributes;
        this.state = state;
        this.authorizationCodeValue = authorizationCodeValue;
        this.authorizationCodeIssuedAt = authorizationCodeIssuedAt;
        this.authorizationCodeExpiresAt = authorizationCodeExpiresAt;
        this.authorizationCodeMetadata = authorizationCodeMetadata;
        this.accessTokenValue = accessTokenValue;
        this.accessTokenIssuedAt = accessTokenIssuedAt;
        this.accessTokenExpiresAt = accessTokenExpiresAt;
        this.accessTokenMetadata = accessTokenMetadata;
        this.accessTokenType = accessTokenType;
        this.accessTokenScopes = accessTokenScopes;
        this.refreshTokenValue = refreshTokenValue;
        this.refreshTokenIssuedAt = refreshTokenIssuedAt;
        this.refreshTokenExpiresAt = refreshTokenExpiresAt;
        this.refreshTokenMetadata = refreshTokenMetadata;
    }

    @Column("id")
    public String id() {
        return id;
    }

    @Column("account_id")
    public UUID accountId() {
        return accountId;
    }

    @Column("application_client_id")
    public UUID applicationClientId() {
        return applicationClientId;
    }

    @Column("creation_time")
    public Instant creationTime() {
        return creationTime;
    }

    @Column("last_update_time")
    public Instant lastUpdateTime() {
        return lastUpdateTime;
    }

    @Column("display_name")
    public String displayName() {
        return displayName;
    }

    @Column("authorization_grant_type")
    public String authorizationGrantType() {
        return authorizationGrantType;
    }

    @Column("authorized_scopes")
    public Set<String> authorizedScopes() {
        return authorizedScopes;
    }

    @Column("attributes")
    public String attributes() {
        return attributes;
    }

    @Column("state")
    public String state() {
        return state;
    }

    @Column("authorization_code_value")
    public String authorizationCodeValue() {
        return authorizationCodeValue;
    }

    @Column("authorization_code_issued_at")
    public Instant authorizationCodeIssuedAt() {
        return authorizationCodeIssuedAt;
    }

    @Column("authorization_code_expires_at")
    public Instant authorizationCodeExpiresAt() {
        return authorizationCodeExpiresAt;
    }

    @Column("authorization_code_metadata")
    public String authorizationCodeMetadata() {
        return authorizationCodeMetadata;
    }

    @Column("access_token_value")
    public String accessTokenValue() {
        return accessTokenValue;
    }

    @Column("access_token_issued_at")
    public Instant accessTokenIssuedAt() {
        return accessTokenIssuedAt;
    }

    @Column("access_token_expires_at")
    public Instant accessTokenExpiresAt() {
        return accessTokenExpiresAt;
    }

    @Column("access_token_metadata")
    public String accessTokenMetadata() {
        return accessTokenMetadata;
    }

    @Column("access_token_type")
    public String accessTokenType() {
        return accessTokenType;
    }

    @Column("access_token_scopes")
    public Set<String> accessTokenScopes() {
        return accessTokenScopes;
    }

    @Column("refresh_token_value")
    public String refreshTokenValue() {
        return refreshTokenValue;
    }

    @Column("refresh_token_issued_at")
    public Instant refreshTokenIssuedAt() {
        return refreshTokenIssuedAt;
    }

    @Column("refresh_token_expires_at")
    public Instant refreshTokenExpiresAt() {
        return refreshTokenExpiresAt;
    }

    @Column("refresh_token_metadata")
    public String refreshTokenMetadata() {
        return refreshTokenMetadata;
    }
}
