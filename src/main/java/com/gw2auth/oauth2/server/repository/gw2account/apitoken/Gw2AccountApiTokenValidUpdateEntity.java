package com.gw2auth.oauth2.server.repository.gw2account.apitoken;

import com.gw2auth.oauth2.server.service.Gw2ApiPermission;

import java.util.Set;
import java.util.UUID;

public record Gw2AccountApiTokenValidUpdateEntity(UUID accountId, UUID gw2AccountId, Set<Gw2ApiPermission> gw2ApiPermissions, boolean isValid) {
}
