package com.gw2auth.oauth2.server.repository.account;

import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

@Table("account_federations")
public record AccountFederationEntity(@Column("issuer") String issuer,
                                      @Column("id_at_issuer") String idAtIssuer,
                                      @Column("account_id") long accountId) {

}
