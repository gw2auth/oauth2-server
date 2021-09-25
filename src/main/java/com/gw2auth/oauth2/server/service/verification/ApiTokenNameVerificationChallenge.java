package com.gw2auth.oauth2.server.service.verification;

import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.util.Utils;
import com.gw2auth.oauth2.server.service.gw2.Gw2ApiService;
import com.gw2auth.oauth2.server.service.gw2.Gw2TokenInfo;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;

@Component
public class ApiTokenNameVerificationChallenge implements VerificationChallenge<String> {

    private static final long ID = 1;
    private static final String NAME = "API-Token Name";
    private static final String DESCRIPTION = """
            <p class="mb-1">When choosing this verification challenge, we will randomly generate a name that you should use to either change the name of a existing API-Token or create a new one with</p>
            <p class="mb-0">The verification process can take up to 90 minutes due to the refresh interval of the GW2-API</p>
            """;
    private static final String MESSAGE = """
            <p class="mb-1">Create a new API-Token or update the name of a existing and linked one <a href="https://account.arena.net/applications" target="_blank">on the Website of ArenaNet</a></p>
            <p class="mb-0">The name of the API-Token must start with <strong>%s</strong></p>
            """;
    private static final Set<Gw2ApiPermission> REQUIRED_GW2_API_PERMISSIONS = Collections.unmodifiableSet(EnumSet.noneOf(Gw2ApiPermission.class));
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
    public String getName() {
        return NAME;
    }

    @Override
    public String getDescription() {
        return DESCRIPTION;
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
    public String buildMessage(String state, Locale locale) {
        return String.format(MESSAGE, state);
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
