package com.gw2auth.oauth2.server.service.user;

import com.fasterxml.jackson.annotation.*;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.UUID;

/*
Has to be kept here to support old issued authorizations
 */
@Deprecated
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.NONE, getterVisibility = JsonAutoDetect.Visibility.NONE,
        isGetterVisibility = JsonAutoDetect.Visibility.NONE, setterVisibility = JsonAutoDetect.Visibility.NONE,
        creatorVisibility = JsonAutoDetect.Visibility.NONE)
public abstract class Gw2AuthUserMixin {

    @JsonCreator
    Gw2AuthUserMixin(@JsonProperty("parent") OAuth2User parent, @JsonProperty("accountId") UUID accountId) {

    }

    @JsonGetter("parent")
    abstract OAuth2User getParent();

    @JsonGetter("accountId")
    abstract UUID getAccountId();
}