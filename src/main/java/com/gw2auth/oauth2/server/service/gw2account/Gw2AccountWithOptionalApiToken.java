package com.gw2auth.oauth2.server.service.gw2account;

import com.gw2auth.oauth2.server.service.gw2account.apitoken.Gw2AccountApiToken;

import java.util.Optional;

public record Gw2AccountWithOptionalApiToken(Gw2Account account, Gw2AccountApiToken apiToken) {

    @Override
    public Gw2AccountApiToken apiToken() {
        throw new UnsupportedOperationException();
    }

    public Optional<Gw2AccountApiToken> optionalApiToken() {
        return Optional.ofNullable(this.apiToken);
    }
}
