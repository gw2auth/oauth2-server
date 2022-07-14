package com.gw2auth.oauth2.server.repository.client.consent;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Table("client_consent_logs")
public record ClientConsentLogEntity(@Id @Column("id") UUID id,
                                     @Column("account_id") UUID accountId,
                                     @Column("client_registration_id") UUID clientRegistrationId,
                                     @Column("timestamp") Instant timestamp,
                                     @Column("type") String type,
                                     @Column("messages") List<String> messages) {

}
