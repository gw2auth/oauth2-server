package com.gw2auth.oauth2.server.repository.gw2account;

import com.gw2auth.oauth2.server.repository.gw2account.apitoken.Gw2AccountApiTokenEntity;
import org.jspecify.annotations.Nullable;
import org.springframework.data.relational.core.mapping.Embedded;

import java.util.Optional;

public record Gw2AccountWithOptionalApiTokenEntity(@Embedded.Empty(prefix = "acc_") Gw2AccountEntity account,
                                                   @Embedded.Nullable(prefix = "tk_") @Nullable Gw2AccountApiTokenEntity token) {

    /** @deprecated Use {@link #optionalToken()} instead */
    @Deprecated
    @Override
    public Gw2AccountApiTokenEntity token() {
        throw new UnsupportedOperationException();
    }

    public Optional<Gw2AccountApiTokenEntity> optionalToken() {
        return Optional.ofNullable(this.token);
    }
}
