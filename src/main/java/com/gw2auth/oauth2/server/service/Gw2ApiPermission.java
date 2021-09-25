package com.gw2auth.oauth2.server.service;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.*;
import java.util.stream.Stream;

public enum Gw2ApiPermission {

    ACCOUNT("account"),
    BUILDS("builds"),
    CHARACTERS("characters"),
    GUILDS("guilds"),
    INVENTORIES("inventories"),
    PROGRESSION("progression"),
    PVP("pvp"),
    TRADINGPOST("tradingpost"),
    UNLOCKS("unlocks"),
    WALLET("wallet");

    private static final List<Gw2ApiPermission> VALUES = List.of(values());
    private static final Set<Gw2ApiPermission> ALL = Set.copyOf(EnumSet.allOf(Gw2ApiPermission.class));
    private static final Map<String, Gw2ApiPermission> BY_GW2;
    private static final Map<String, Gw2ApiPermission> BY_OAUTH2;
    static {
        final Map<String, Gw2ApiPermission> byGw2 = new HashMap<>(VALUES.size());
        final Map<String, Gw2ApiPermission> byOauth2 = new HashMap<>(VALUES.size());

        for (Gw2ApiPermission gw2ApiPermission : VALUES) {
            byGw2.put(gw2ApiPermission.gw2(), gw2ApiPermission);
            byOauth2.put(gw2ApiPermission.oauth2(), gw2ApiPermission);
        }

        BY_GW2 = Map.copyOf(byGw2);
        BY_OAUTH2 = Map.copyOf(byOauth2);
    }

    private final String value;

    Gw2ApiPermission(String value) {
        this.value = value;
    }

    @JsonValue
    public String gw2() {
        return this.value;
    }

    public String oauth2() {
        return "gw2:" + this.value;
    }

    public static Optional<Gw2ApiPermission> fromOAuth2(String oauth2) {
        return Optional.ofNullable(BY_OAUTH2.get(oauth2));
    }

    public static Optional<Gw2ApiPermission> fromGw2(String gw2) {
        return Optional.ofNullable(BY_GW2.get(gw2));
    }

    public static boolean contains(Gw2ApiPermission gw2ApiPermission) {
        return ALL.contains(gw2ApiPermission);
    }

    public static Stream<Gw2ApiPermission> stream() {
        return VALUES.stream();
    }

    @JsonCreator
    static Gw2ApiPermission fromGw2Required(String gw2) {
        return fromGw2(gw2).orElseThrow();
    }
}
