package com.gw2auth.oauth2.server.repository.client.registration;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.Set;

@Table("client_registrations")
public record ClientRegistrationEntity(@Id @Column("id") Long id,
                                       @Column("account_id") long accountId,
                                       @Column("creation_time") Instant creationTime,
                                       @Column("display_name") String displayName,
                                       @Column("client_id") String clientId,
                                       @Column("client_secret") String clientSecret,
                                       @Column("authorization_grant_types") Set<String> authorizationGrantTypes,
                                       @Column("redirect_uris") Set<String> redirectUris) {

    public ClientRegistrationEntity withClientSecret(String clientSecret) {
        return new ClientRegistrationEntity(
                this.id,
                this.accountId,
                this.creationTime,
                this.displayName,
                this.clientId,
                clientSecret,
                this.authorizationGrantTypes,
                this.redirectUris
        );
    }
}
