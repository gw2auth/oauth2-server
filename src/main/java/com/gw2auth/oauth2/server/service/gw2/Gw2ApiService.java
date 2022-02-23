package com.gw2auth.oauth2.server.service.gw2;

import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.util.SupplierWithExc;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

public interface Gw2ApiService {

    Gw2TokenInfo getTokenInfo(String gw2ApiToken);

    Gw2Account getAccount(String gw2ApiToken);

    Gw2SubToken createSubToken(String token, Set<Gw2ApiPermission> permissions, Instant expirationTime);

    List<Gw2Transaction> getCurrentBuyTransactions(String gw2ApiToken);

    <T, EXC extends Exception> T withTimeout(long timeout, TimeUnit timeUnit, SupplierWithExc<T, EXC> supplierWithExc) throws EXC;
}
