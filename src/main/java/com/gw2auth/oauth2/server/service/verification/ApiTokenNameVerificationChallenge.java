package com.gw2auth.oauth2.server.service.verification;

import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.util.Utils;
import com.gw2auth.oauth2.server.service.gw2.Gw2ApiService;
import com.gw2auth.oauth2.server.service.gw2.Gw2TokenInfo;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

@Component
public class ApiTokenNameVerificationChallenge implements VerificationChallenge<String> {

    private static final long ID = 1;
    private static final Set<Gw2ApiPermission> REQUIRED_GW2_API_PERMISSIONS = Collections.unmodifiableSet(EnumSet.of(Gw2ApiPermission.ACCOUNT));
    private static final Duration TIMEOUT = Duration.ofMinutes(90L);
    private static final String API_TOKEN_VERIFICATION_PREFIX = "GW2Hub-";

    private final Gw2ApiService gw2ApiService;

    public ApiTokenNameVerificationChallenge(Gw2ApiService gw2ApiService) {
        this.gw2ApiService = gw2ApiService;
    }

    @Override
    public long getId() {
        return ID;
    }

    @Override
    public Set<Gw2ApiPermission> getRequiredGw2ApiPermissions() {
        return REQUIRED_GW2_API_PERMISSIONS;
    }

    @Override
    public Duration getTimeout() {
        return TIMEOUT;
    }

    @Override
    public Map<String, Object> buildMessage(String state, Locale locale) {
        return Map.of("apiTokenName", state);
    }

    @Override
    public String start() {
        final int rand = ThreadLocalRandom.current().nextInt(0xFFFFFF + 1);
        return API_TOKEN_VERIFICATION_PREFIX + Utils.lpad(Integer.toHexString(rand), '0', 8);
    }

    @Override
    public boolean verify(String state, String gw2ApiToken) {
        final Gw2TokenInfo tokenInfo = this.gw2ApiService.getTokenInfo(gw2ApiToken);
        return tokenInfo.name().trim().toLowerCase().startsWith(state.toLowerCase());
    }
}
