package com.gw2auth.oauth2.server.repository.client.consent;

import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

@Table("client_consents")
public record ClientConsentEntity(@Column("account_id") UUID accountId,
                                  @Column("client_registration_id") UUID clientRegistrationId,
                                  @Column("account_sub") UUID accountSub,
                                  @Column("authorized_scopes") Set<String> authorizedScopes) {

    public ClientConsentEntity withAuthorizedScopes(Set<String> authorizedScopes) {
        return new ClientConsentEntity(this.accountId, this.clientRegistrationId, this.accountSub, authorizedScopes);
    }

    public ClientConsentEntity withAdditionalScopes(Set<String> authorizedScopes) {
        final Set<String> scopes = new HashSet<>(this.authorizedScopes);
        scopes.addAll(authorizedScopes);

        return withAuthorizedScopes(scopes);
    }
}
