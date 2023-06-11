package com.gw2auth.oauth2.server.repository.gw2account;

import com.gw2auth.oauth2.server.repository.gw2account.apitoken.Gw2AccountApiTokenEntity;
import org.springframework.data.relational.core.mapping.Embedded;

public record Gw2AccountWithApiTokenEntity(@Embedded.Empty(prefix = "acc_") Gw2AccountEntity account,
                                           @Embedded.Empty(prefix = "tk_") Gw2AccountApiTokenEntity token) {
}
