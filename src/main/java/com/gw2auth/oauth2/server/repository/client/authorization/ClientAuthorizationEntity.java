package com.gw2auth.oauth2.server.repository.client.authorization;

import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.util.Set;
import java.util.UUID;

@Table("client_authorizations")
public record ClientAuthorizationEntity(@Column("account_id") long accountId,
                                        @Column("client_registration_id") long clientRegistrationId,
                                        @Column("account_sub") UUID accountSub,
                                        @Column("authorized_scopes") Set<String> authorizedScopes) {

    public ClientAuthorizationEntity withAuthorizedScopes(Set<String> authorizedScopes) {
        return new ClientAuthorizationEntity(this.accountId, this.clientRegistrationId, this.accountSub, authorizedScopes);
    }
}
