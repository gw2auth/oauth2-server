package com.gw2auth.oauth2.server.repository.gw2account;

import com.gw2auth.oauth2.server.repository.gw2account.apitoken.Gw2AccountApiTokenEntity;
import org.springframework.data.relational.core.mapping.Embedded;

import java.util.Optional;

public record Gw2AccountWithOptionalApiTokenEntity(@Embedded.Empty(prefix = "acc_") Gw2AccountEntity account,
                                                   @Embedded.Nullable(prefix = "tk_") Gw2AccountApiTokenEntity token) {

    @Override
    public Gw2AccountApiTokenEntity token() {
        throw new UnsupportedOperationException();
    }

    public Optional<Gw2AccountApiTokenEntity> tokenOptional() {
        return Optional.ofNullable(this.token);
    }
}
