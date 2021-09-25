package com.gw2auth.oauth2.server.service.gw2;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;

import java.util.Set;

public record Gw2TokenInfo(@JsonProperty("name") String name, @JsonProperty("permissions") Set<Gw2ApiPermission> permissions) {
}
