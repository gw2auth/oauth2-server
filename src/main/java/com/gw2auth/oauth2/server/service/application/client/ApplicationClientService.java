package com.gw2auth.oauth2.server.service.application.client;

import com.gw2auth.oauth2.server.service.OAuth2ClientApiVersion;
import com.gw2auth.oauth2.server.service.OAuth2ClientType;

import java.util.*;

public interface ApplicationClientService {

    Optional<ApplicationClient> getApplicationClient(UUID id);
    ApplicationClientCreation createApplicationClient(UUID accountId, UUID applicationId, String displayName, Set<String> authorizationGrantTypes, Set<String> redirectUris, OAuth2ClientApiVersion clientApiVersion, OAuth2ClientType clientType);
}
