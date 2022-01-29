package com.gw2auth.oauth2.server.repository.apisubtoken;

import java.util.Collection;

public interface CustomApiSubTokenRepository {

    void saveAll(Collection<ApiSubTokenEntity> entities);
}
