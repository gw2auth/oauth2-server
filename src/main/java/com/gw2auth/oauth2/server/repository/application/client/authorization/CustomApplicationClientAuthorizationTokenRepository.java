package com.gw2auth.oauth2.server.repository.application.client.authorization;

import java.util.Collection;

public interface CustomApplicationClientAuthorizationTokenRepository {

    void saveAll(Collection<ApplicationClientAuthorizationTokenEntity> entities);
}
