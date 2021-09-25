package com.gw2auth.oauth2.server.service.gw2;

import com.gw2auth.oauth2.server.service.Gw2ApiPermission;

import java.time.Instant;
import java.util.List;
import java.util.Set;

public interface Gw2ApiService {

    Gw2TokenInfo getTokenInfo(String gw2ApiToken);

    Gw2Account getAccount(String gw2ApiToken);

    Gw2SubToken createSubToken(String token, Set<Gw2ApiPermission> permissions, Instant expirationTime);

    Gw2Item getItem(int itemId);

    List<Gw2Transaction> getCurrentBuyTransactions(String gw2ApiToken);
}
