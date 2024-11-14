package com.gw2auth.oauth2.server.service.application.client;

import org.jspecify.annotations.Nullable;

public record ApplicationClientCreation(ApplicationClient client, @Nullable String clientSecret) {
}
