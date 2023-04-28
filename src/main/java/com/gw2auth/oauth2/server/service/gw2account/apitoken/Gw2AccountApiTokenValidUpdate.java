package com.gw2auth.oauth2.server.service.gw2account.apitoken;

import java.util.UUID;

public record Gw2AccountApiTokenValidUpdate(UUID accountId, UUID gw2AccountId, boolean isValid) {
}
