package com.gw2auth.oauth2.server.repository.account;

import java.util.Collection;

public interface CustomAccountLogRepository {

    void saveAll(Collection<AccountLogEntity> entities);
}
