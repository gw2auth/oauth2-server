package com.gw2auth.oauth2.server.service.apitoken;

import com.gw2auth.oauth2.server.repository.apitoken.ApiTokenEntity;
import com.gw2auth.oauth2.server.service.Gw2ApiPermission;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public record ApiToken(UUID gw2AccountId, Instant creationTime, String gw2ApiToken, String displayName, Set<Gw2ApiPermission> gw2ApiPermissions) {

    public static ApiToken fromEntity(ApiTokenEntity entity) {
        final Set<Gw2ApiPermission> gw2ApiPermissions = entity.gw2ApiPermissions().stream()
                .flatMap((v) -> Gw2ApiPermission.fromGw2(v).stream())
                .collect(Collectors.toSet());

        return new ApiToken(entity.gw2AccountId(), entity.creationTime(), entity.gw2ApiToken(), entity.displayName(), gw2ApiPermissions);
    }
}
