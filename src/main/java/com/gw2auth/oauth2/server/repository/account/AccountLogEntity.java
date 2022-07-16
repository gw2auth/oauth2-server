package com.gw2auth.oauth2.server.repository.account;

import org.json.JSONObject;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import java.util.UUID;

@Table("account_logs")
public record AccountLogEntity(@Id @Column("id") UUID id,
                               @Column("account_id") UUID accountId,
                               @Column("timestamp") Instant timestamp,
                               @Column("message") String message,
                               @Column("fields") JSONObject fields,
                               @Column("persistent") boolean persistent) {
}
