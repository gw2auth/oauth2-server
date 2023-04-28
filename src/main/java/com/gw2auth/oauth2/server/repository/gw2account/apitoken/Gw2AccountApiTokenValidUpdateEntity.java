package com.gw2auth.oauth2.server.repository.gw2account.apitoken;

import java.util.UUID;

public record Gw2AccountApiTokenValidUpdateEntity(UUID accountId, UUID gw2AccountId, boolean isValid) {
}
