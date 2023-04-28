package com.gw2auth.oauth2.server.service.application;

import java.util.Optional;
import java.util.UUID;

public interface ApplicationService {

    Optional<Application> getApplication(UUID id);
    Application createApplication(UUID accountId, String displayName);
    void deleteApplication(UUID accountId, UUID id);
}
