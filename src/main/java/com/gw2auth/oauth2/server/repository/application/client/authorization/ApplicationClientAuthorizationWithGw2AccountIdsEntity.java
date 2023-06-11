package com.gw2auth.oauth2.server.repository.application.client.authorization;

import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Embedded;

import java.util.Set;
import java.util.UUID;

public record ApplicationClientAuthorizationWithGw2AccountIdsEntity(@Embedded.Empty ApplicationClientAuthorizationEntity authorization,
                                                                    @Column("gw2_account_ids") Set<UUID> gw2AccountIds) {

}
