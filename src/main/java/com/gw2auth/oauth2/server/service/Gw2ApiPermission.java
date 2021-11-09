package com.gw2auth.oauth2.server.service;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum Gw2ApiPermission {

    ACCOUNT("account", 0),
    BUILDS("builds", 1),
    CHARACTERS("characters", 2),
    GUILDS("guilds", 3),
    INVENTORIES("inventories", 4),
    PROGRESSION("progression", 5),
    PVP("pvp", 6),
    TRADINGPOST("tradingpost", 7),
    UNLOCKS("unlocks", 8),
    WALLET("wallet", 9);

    private static final List<Gw2ApiPermission> VALUES = List.of(values());
    private static final Set<Gw2ApiPermission> ALL = Set.copyOf(EnumSet.allOf(Gw2ApiPermission.class));
    private static final Map<String, Gw2ApiPermission> BY_GW2;
    private static final Map<String, Gw2ApiPermission> BY_OAUTH2;
    static {
        final Map<String, Gw2ApiPermission> byGw2 = new HashMap<>(VALUES.size());
        final Map<String, Gw2ApiPermission> byOauth2 = new HashMap<>(VALUES.size());
        int flagAll = 0;

        for (Gw2ApiPermission gw2ApiPermission : VALUES) {
            if (byGw2.put(gw2ApiPermission.gw2(), gw2ApiPermission) != null) {
                throw new IllegalStateException("invalid configuration: gw2 value " + gw2ApiPermission.gw2() + " already present");
            }

            if (byOauth2.put(gw2ApiPermission.oauth2(), gw2ApiPermission) != null) {
                throw new IllegalStateException("invalid configuration: oauth2 value " + gw2ApiPermission.oauth2() + " already present");
            }

            if ((flagAll & gw2ApiPermission.flag) == 0) {
                flagAll |= gw2ApiPermission.flag;
            } else {
                throw new IllegalStateException("invalid configuration: flag " + Integer.toBinaryString(gw2ApiPermission.flag) + " already present");
            }
        }

        BY_GW2 = Map.copyOf(byGw2);
        BY_OAUTH2 = Map.copyOf(byOauth2);
    }

    private final String value;
    private final int flag;

    Gw2ApiPermission(String value, int nthBitFlag) {
        this.value = value;
        this.flag = 1 << nthBitFlag;
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

    public static Set<Gw2ApiPermission> fromBitSet(int bitSet) {
        return stream()
                .filter((gw2ApiPermission) -> (bitSet & gw2ApiPermission.flag) == gw2ApiPermission.flag)
                .collect(Collectors.toSet());
    }

    public static int toBitSet(Collection<Gw2ApiPermission> gw2ApiPermissions) {
        int bitSet = 0;

        for (Gw2ApiPermission gw2ApiPermission : gw2ApiPermissions) {
            bitSet |= gw2ApiPermission.flag;
        }

        return bitSet;
    }

    public static boolean contains(Gw2ApiPermission gw2ApiPermission) {
        return ALL.contains(gw2ApiPermission);
    }

    public static Stream<Gw2ApiPermission> stream() {
        return VALUES.stream();
    }

    public static Set<Gw2ApiPermission> all() {
        return ALL;
    }

    @JsonCreator
    static Gw2ApiPermission fromGw2Required(String gw2) {
        return fromGw2(gw2).orElseThrow();
    }
}
