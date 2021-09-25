package com.gw2auth.oauth2.server.service.gw2;

import com.gw2auth.oauth2.server.service.Gw2ApiPermission;

import java.util.Set;

public record Gw2SubToken(String value, Set<Gw2ApiPermission> permissions) {

}
