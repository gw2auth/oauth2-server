package com.gw2auth.oauth2.server.repository.apitoken;

import java.util.UUID;

public record ApiTokenValidityUpdateEntity(UUID accountId, UUID gw2AccountId, boolean isValid) {
}
