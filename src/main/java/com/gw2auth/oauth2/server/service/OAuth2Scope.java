package com.gw2auth.oauth2.server.service;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum OAuth2Scope {

    // region gw2
    GW2_ACCOUNT("gw2:account", EnumSet.allOf(OAuth2ClientApiVersion.class)),
    GW2_BUILDS("gw2:builds", EnumSet.allOf(OAuth2ClientApiVersion.class)),
    GW2_CHARACTERS("gw2:characters", EnumSet.allOf(OAuth2ClientApiVersion.class)),
    GW2_GUILDS("gw2:guilds", EnumSet.allOf(OAuth2ClientApiVersion.class)),
    GW2_INVENTORIES("gw2:inventories", EnumSet.allOf(OAuth2ClientApiVersion.class)),
    GW2_PROGRESSION("gw2:progression", EnumSet.allOf(OAuth2ClientApiVersion.class)),
    GW2_PVP("gw2:pvp", EnumSet.allOf(OAuth2ClientApiVersion.class)),
    GW2_TRADINGPOST("gw2:tradingpost", EnumSet.allOf(OAuth2ClientApiVersion.class)),
    GW2_UNLOCKS("gw2:unlocks", EnumSet.allOf(OAuth2ClientApiVersion.class)),
    GW2_WALLET("gw2:wallet", EnumSet.allOf(OAuth2ClientApiVersion.class)),
    // endregion

    // region v0
    GW2AUTH_VERIFIED("gw2auth:verified", EnumSet.of(OAuth2ClientApiVersion.V0)),
    // endregion

    // region v1
    ID("id", EnumSet.of(OAuth2ClientApiVersion.V1)),
    GW2ACC_NAME("gw2acc:name", EnumSet.of(OAuth2ClientApiVersion.V1)),
    GW2ACC_DISPLAY_NAME("gw2acc:display_name", EnumSet.of(OAuth2ClientApiVersion.V1)),
    GW2ACC_VERIFIED("gw2acc:verified", EnumSet.of(OAuth2ClientApiVersion.V1)),
    // GW2AUTH_KV_GET("gw2auth:kv:get", EnumSet.of(OAuth2ClientApiVersion.V1)),
    // GW2AUTH_KV_PUT("gw2auth:kv:put", EnumSet.of(OAuth2ClientApiVersion.V1)),
    ;

    private static final Set<OAuth2Scope> ALL = Collections.unmodifiableSet(EnumSet.allOf(OAuth2Scope.class));
    private static final Set<OAuth2Scope> ALL_V0;
    private static final Set<OAuth2Scope> ALL_V1;
    private static final Set<OAuth2Scope> GW2_ACCOUNT_RELATED;
    private static final Map<String, OAuth2Scope> BY_VALUE;
    static {
        ALL_V0 = ALL.stream().filter((v) -> v.isSupported(OAuth2ClientApiVersion.V0)).collect(Collectors.toUnmodifiableSet());
        ALL_V1 = ALL.stream().filter((v) -> v.isSupported(OAuth2ClientApiVersion.V1)).collect(Collectors.toUnmodifiableSet());

        GW2_ACCOUNT_RELATED = EnumSet.of(
                GW2_ACCOUNT, GW2_BUILDS, GW2_CHARACTERS, GW2_GUILDS, GW2_INVENTORIES, GW2_PROGRESSION, GW2_PVP, GW2_TRADINGPOST, GW2_UNLOCKS, GW2_WALLET,
                GW2AUTH_VERIFIED,
                GW2ACC_NAME, GW2ACC_DISPLAY_NAME, GW2ACC_VERIFIED
        );

        final Map<String, OAuth2Scope> byValue = new HashMap<>();

        for (OAuth2Scope scope : ALL) {
            if (byValue.put(scope.oauth2(), scope) != null) {
                throw new IllegalStateException("duplicate value " + scope.oauth2());
            }
        }

        BY_VALUE = Map.copyOf(byValue);
    }

    private final String value;
    private final Set<OAuth2ClientApiVersion> supportedVersions;

    OAuth2Scope(String value, Set<OAuth2ClientApiVersion> supportedVersions) {
        this.value = value;
        this.supportedVersions = supportedVersions;
    }

    @JsonValue
    public String oauth2() {
        return this.value;
    }

    public boolean isSupported(OAuth2ClientApiVersion version) {
        return this.supportedVersions.contains(version);
    }

    public static Optional<OAuth2Scope> fromOAuth2(String value) {
        return Optional.ofNullable(BY_VALUE.get(value));
    }

    public static OAuth2Scope fromOAuth2Required(String value) {
        return fromOAuth2(value).orElseThrow(IllegalArgumentException::new);
    }

    public static boolean containsAnyGw2AccountRelatedScopes(Set<OAuth2Scope> scopes) {
        return scopes.stream().anyMatch(OAuth2Scope::isGw2AccountRelatedScope);
    }

    public static boolean isGw2AuthVerifiedScope(OAuth2Scope scope) {
        return scope == GW2AUTH_VERIFIED || scope == GW2ACC_VERIFIED;
    }

    public static boolean isGw2AccountRelatedScope(OAuth2Scope scope) {
        return GW2_ACCOUNT_RELATED.contains(scope);
    }

    public static Stream<OAuth2Scope> allForVersion(OAuth2ClientApiVersion clientApiVersion) {
        return (switch (clientApiVersion) {
            case V0 -> ALL_V0;
            case V1 -> ALL_V1;
        }).stream();
    }

    @JsonCreator
    public static OAuth2Scope fromJson(String value) {
        return fromOAuth2Required(value);
    }
}
