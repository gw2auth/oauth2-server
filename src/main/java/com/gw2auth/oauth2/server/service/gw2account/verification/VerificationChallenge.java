package com.gw2auth.oauth2.server.service.gw2account.verification;

import com.gw2auth.oauth2.server.service.Gw2ApiPermission;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.Set;

public interface VerificationChallenge<S> {

    long getId();
    Set<Gw2ApiPermission> getRequiredGw2ApiPermissions();
    Duration getTimeout();
    S readState(String rawState) throws IOException;
    String writeState(S state) throws IOException;
    Map<String, Object> buildMessage(S state);

    S start();
    boolean verify(S state, String gw2ApiToken);
}
