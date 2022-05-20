package com.gw2auth.oauth2.server.service.verification;

import com.gw2auth.oauth2.server.service.Gw2ApiPermission;
import com.gw2auth.oauth2.server.service.gw2.Gw2ApiService;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;

@Component
public class CharacterNameVerificationChallenge implements VerificationChallenge<String> {

    private static final long ID = 3;
    private static final Set<Gw2ApiPermission> REQUIRED_GW2_API_PERMISSIONS = Collections.unmodifiableSet(EnumSet.of(Gw2ApiPermission.ACCOUNT, Gw2ApiPermission.CHARACTERS));
    private static final Duration TIMEOUT = Duration.ofMinutes(15L);
    private static final String CHARACTER_NAME_VERIFICATION_PREFIX = "Gw2auth ";
    private static final String SUFFIX_CHARACTERS = "abcdefghijklmnopqrstuvwxyz";

    private final Gw2ApiService gw2ApiService;

    public CharacterNameVerificationChallenge(Gw2ApiService gw2ApiService) {
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
    public String readState(String rawState) {
        return rawState;
    }

    @Override
    public String writeState(String state) {
        return state;
    }

    @Override
    public Map<String, Object> buildMessage(String state) {
        return Map.of("characterName", state);
    }

    @Override
    public String start() {
        String suffix = ThreadLocalRandom.current().ints(8L, 0, SUFFIX_CHARACTERS.length())
                .mapToObj(SUFFIX_CHARACTERS::charAt)
                .map((c) -> Character.toString(c))
                .collect(Collectors.joining());

        suffix = Character.toUpperCase(suffix.charAt(0)) + suffix.substring(1).toLowerCase();

        return CHARACTER_NAME_VERIFICATION_PREFIX + suffix;
    }

    @Override
    public boolean verify(String state, String gw2ApiToken) {
        final List<String> characters = this.gw2ApiService.getCharacters(gw2ApiToken);
        return characters.stream().anyMatch((v) -> v.equalsIgnoreCase(state));
    }
}
