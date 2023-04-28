package com.gw2auth.oauth2.server.repository.gw2account.apitoken;

import java.time.Instant;
import java.util.Collection;

public interface CustomGw2AccountApiTokenRepository {

    void updateApiTokensValid(Instant lastValidCheckTime, Collection<Gw2AccountApiTokenValidUpdateEntity> updates);
}
