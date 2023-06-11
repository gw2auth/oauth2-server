package com.gw2auth.oauth2.server.repository.application.account;

import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Embedded;

import java.util.UUID;

public record ApplicationAccountWithSubEntity(@Embedded.Empty ApplicationAccountEntity account, @Column("account_sub") UUID accountSub) {

}
