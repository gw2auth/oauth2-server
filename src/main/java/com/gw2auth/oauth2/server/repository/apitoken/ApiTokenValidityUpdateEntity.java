package com.gw2auth.oauth2.server.repository.apitoken;

import java.util.UUID;

public record ApiTokenValidityUpdateEntity(long accountId, UUID gw2AccountId, boolean isValid) {
}
