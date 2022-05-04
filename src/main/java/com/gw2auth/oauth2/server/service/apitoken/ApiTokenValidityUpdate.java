package com.gw2auth.oauth2.server.service.apitoken;

import java.util.UUID;

public record ApiTokenValidityUpdate(long accountId, UUID gw2AccountId, boolean isValid) {
}
