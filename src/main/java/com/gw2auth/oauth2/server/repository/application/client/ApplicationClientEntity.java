package com.gw2auth.oauth2.server.repository.application.client;

import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;

@Table("application_clients")
public record ApplicationClientEntity(@Column("id") UUID id,
                                      @Column("application_id") UUID applicationId,
                                      @Column("creation_time") Instant creationTime,
                                      @Column("display_name") String displayName,
                                      @Column("client_secret") String clientSecret,
                                      @Column("authorization_grant_types") Set<String> authorizationGrantTypes,
                                      @Column("redirect_uris") Set<String> redirectUris,
                                      @Column("requires_approval") boolean requiresApproval) {
}
