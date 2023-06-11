package com.gw2auth.oauth2.server.service.gw2account;

import com.gw2auth.oauth2.server.service.gw2account.apitoken.Gw2AccountApiToken;

public record Gw2AccountWithApiToken(Gw2Account account, Gw2AccountApiToken apiToken) {
}
