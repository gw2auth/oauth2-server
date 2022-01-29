package com.gw2auth.oauth2.server.repository.client.authorization;

import java.util.Collection;

public interface CustomClientAuthorizationTokenRepository {

    void saveAll(Collection<ClientAuthorizationTokenEntity> entities);
}
