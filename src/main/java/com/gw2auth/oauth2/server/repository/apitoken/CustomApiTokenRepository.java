package com.gw2auth.oauth2.server.repository.apitoken;

import java.time.Instant;
import java.util.Collection;

public interface CustomApiTokenRepository {

    void updateApiTokensValid(Instant lastValidCheckTime, Collection<ApiTokenValidityUpdateEntity> updates);
}
