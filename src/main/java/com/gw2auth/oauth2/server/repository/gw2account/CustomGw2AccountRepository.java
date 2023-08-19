package com.gw2auth.oauth2.server.repository.gw2account;

import java.time.Instant;
import java.util.Collection;

public interface CustomGw2AccountRepository {

    void updateGw2AccountNames(Instant lastNameUpdateTime, Collection<Gw2AccountNameUpdateEntity> updates);
}
