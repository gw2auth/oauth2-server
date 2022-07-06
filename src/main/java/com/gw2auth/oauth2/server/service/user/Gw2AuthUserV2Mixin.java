package com.gw2auth.oauth2.server.service.user;

import com.fasterxml.jackson.annotation.*;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.NONE, getterVisibility = JsonAutoDetect.Visibility.NONE,
        isGetterVisibility = JsonAutoDetect.Visibility.NONE, setterVisibility = JsonAutoDetect.Visibility.NONE,
        creatorVisibility = JsonAutoDetect.Visibility.NONE)
public abstract class Gw2AuthUserV2Mixin {

    @JsonCreator
    Gw2AuthUserV2Mixin(@JsonProperty("accountId") long accountId, @JsonProperty("issuer") String issuer, @JsonProperty("idAtIssuer") String idAtIssuer) {

    }

    @JsonGetter("accountId")
    abstract long getAccountId();

    @JsonGetter("issuer")
    abstract String getIssuer();

    @JsonGetter("idAtIssuer")
    abstract String getIdAtIssuer();
}
