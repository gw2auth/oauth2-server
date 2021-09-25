package com.gw2auth.oauth2.server.service.apitoken;

import java.util.Collection;
import java.util.List;

public interface ApiTokenService {

    List<ApiToken> getApiTokens(long accountId);

    List<ApiToken> getApiTokens(long accountId, Collection<String> gw2AccountIds);

    ApiToken updateApiToken(long accountId, String gw2AccountId, String gw2ApiToken, String displayName);

    ApiToken addApiToken(long accountId, String gw2ApiToken);

    void deleteApiToken(long accountId, String gw2AccountId);
}
