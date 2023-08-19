package com.gw2auth.oauth2.server.repository.gw2account;

import java.util.UUID;

public record Gw2AccountNameUpdateEntity(UUID accountId, UUID gw2AccountId, String gw2AccountName, boolean hasNameChanged) {
}
