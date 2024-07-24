package com.gw2auth.oauth2.server.service;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum Gw2ApiPermission {

    ACCOUNT("account", 0, OAuth2Scope.GW2_ACCOUNT),
    BUILDS("builds", 1, OAuth2Scope.GW2_BUILDS),
    CHARACTERS("characters", 2, OAuth2Scope.GW2_CHARACTERS),
    GUILDS("guilds", 3, OAuth2Scope.GW2_GUILDS),
    INVENTORIES("inventories", 4, OAuth2Scope.GW2_INVENTORIES),
    PROGRESSION("progression", 5, OAuth2Scope.GW2_PROGRESSION),
    PVP("pvp", 6, OAuth2Scope.GW2_PVP),
    WVW("wvw", 10, OAuth2Scope.GW2_WVW),
    TRADINGPOST("tradingpost", 7, OAuth2Scope.GW2_TRADINGPOST),
    UNLOCKS("unlocks", 8, OAuth2Scope.GW2_UNLOCKS),
    WALLET("wallet", 9, OAuth2Scope.GW2_WALLET),
    ;

    private static final Set<Gw2ApiPermission> ALL = Collections.unmodifiableSet(EnumSet.allOf(Gw2ApiPermission.class));
    private static final Map<String, Gw2ApiPermission> BY_GW2;
    private static final Map<OAuth2Scope, Gw2ApiPermission> BY_SCOPE;
    static {
        final Gw2ApiPermission[] values = values();
        final Map<String, Gw2ApiPermission> byGw2 = new HashMap<>(values.length);
        final Map<OAuth2Scope, Gw2ApiPermission> byScope = new EnumMap<>(OAuth2Scope.class);
        int flagAll = 0;

        for (Gw2ApiPermission gw2ApiPermission : values) {
            if (byGw2.put(gw2ApiPermission.gw2(), gw2ApiPermission) != null) {
                throw new IllegalStateException("invalid configuration: gw2 value " + gw2ApiPermission.gw2() + " already present");
            }

            if (byScope.put(gw2ApiPermission.scope(), gw2ApiPermission) != null) {
                throw new IllegalStateException("invalid configuration: oauth2 value " + gw2ApiPermission.scope() + " already present");
            }

            if ((flagAll & gw2ApiPermission.flag) == 0) {
                flagAll |= gw2ApiPermission.flag;
            } else {
                throw new IllegalStateException("invalid configuration: flag " + Integer.toBinaryString(gw2ApiPermission.flag) + " already present");
            }
        }

        BY_GW2 = Map.copyOf(byGw2);
        BY_SCOPE = Collections.unmodifiableMap(byScope);
    }

    private final String value;
    private final int flag;
    private final OAuth2Scope scope;

    Gw2ApiPermission(String value, int nthBitFlag, OAuth2Scope scope) {
        this.value = value;
        this.flag = 1 << nthBitFlag;
        this.scope = scope;
    }

    @JsonValue
    public String gw2() {
        return this.value;
    }

    public OAuth2Scope scope() {
        return this.scope;
    }

    public static Optional<Gw2ApiPermission> fromGw2(String gw2) {
        return Optional.ofNullable(BY_GW2.get(gw2));
    }

    public static Optional<Gw2ApiPermission> fromScope(OAuth2Scope scope) {
        return Optional.ofNullable(BY_SCOPE.get(scope));
    }

    public static Set<Gw2ApiPermission> fromBitSet(int bitSet) {
        return stream()
                .filter((gw2ApiPermission) -> (bitSet & gw2ApiPermission.flag) == gw2ApiPermission.flag)
                .collect(Collectors.toUnmodifiableSet());
    }

    public static int toBitSet(Collection<Gw2ApiPermission> gw2ApiPermissions) {
        int bitSet = 0;

        for (Gw2ApiPermission gw2ApiPermission : gw2ApiPermissions) {
            bitSet |= gw2ApiPermission.flag;
        }

        return bitSet;
    }

    public static Stream<Gw2ApiPermission> stream() {
        return ALL.stream();
    }

    public static Set<Gw2ApiPermission> all() {
        return ALL;
    }

    @JsonCreator
    static Gw2ApiPermission fromGw2Required(String gw2) {
        return fromGw2(gw2).orElseThrow();
    }
}
