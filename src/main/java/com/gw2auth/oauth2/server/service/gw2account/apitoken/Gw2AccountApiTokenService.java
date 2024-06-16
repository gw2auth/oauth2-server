package com.gw2auth.oauth2.server.service.gw2account.apitoken;

import java.time.Instant;
import java.util.Collection;

public interface Gw2AccountApiTokenService {

    void updateApiTokensValid(Instant lastValidCheckTime, Collection<Gw2AccountApiTokenValidUpdate> updates);
}
