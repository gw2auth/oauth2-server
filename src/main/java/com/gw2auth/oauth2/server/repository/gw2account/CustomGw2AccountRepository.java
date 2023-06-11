package com.gw2auth.oauth2.server.repository.gw2account;

import java.util.Collection;

public interface CustomGw2AccountRepository {

    void updateGw2AccountNames(Collection<Gw2AccountNameUpdateEntity> updates);
}
