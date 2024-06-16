package com.gw2auth.oauth2.server.service.application;

import java.util.UUID;

public interface ApplicationService {

    Application createApplication(UUID accountId, String displayName);
}
