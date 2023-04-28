package com.gw2auth.oauth2.server.repository.gw2account.subtoken;

import java.util.Collection;

public interface CustomGw2AccountApiSubtokenRepository {

    void saveAll(Collection<Gw2AccountApiSubtokenEntity> entities);
}
