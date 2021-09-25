package com.gw2auth.oauth2.server.service.verification;

import com.gw2auth.oauth2.server.service.Gw2ApiPermission;

import java.time.Duration;
import java.util.Locale;
import java.util.Set;

public interface VerificationChallenge<S> {

    long getId();
    String getName();
    String getDescription();
    Set<Gw2ApiPermission> getRequiredGw2ApiPermissions();
    Duration getTimeout();
    String buildMessage(S state, Locale locale);

    S start();
    boolean verify(S state, String gw2ApiToken);
}
