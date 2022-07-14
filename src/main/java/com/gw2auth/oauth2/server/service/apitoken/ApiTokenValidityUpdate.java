package com.gw2auth.oauth2.server.service.apitoken;

import java.util.UUID;

public record ApiTokenValidityUpdate(UUID accountId, UUID gw2AccountId, boolean isValid) {
}
