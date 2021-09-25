package com.gw2auth.oauth2.server.repository.client.authorization;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.List;

@Table("client_authorization_logs")
public record ClientAuthorizationLogEntity(@Id @Column("id") Long id,
                                           @Column("account_id") long accountId,
                                           @Column("client_registration_id") long clientRegistrationId,
                                           @Column("timestamp") Instant timestamp,
                                           @Column("messages") List<String> messages) {

}
