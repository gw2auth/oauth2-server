package com.gw2auth.oauth2.server.service.client.authorization;

import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationEntity;
import com.gw2auth.oauth2.server.repository.client.authorization.ClientAuthorizationTokenEntity;

import java.time.Instant;
import java.util.*;

public record ClientAuthorization(long accountId, long clientRegistrationId, UUID accountSub, Set<String> authorizedScopes, Map<String, Token> tokens) {

    public static ClientAuthorization fromEntity(ClientAuthorizationEntity entity, List<ClientAuthorizationTokenEntity> tokenEntities) {
        final Set<String> authorizedScopes;
        final Map<String, Token> tokens = new HashMap<>(tokenEntities.size());

        if (entity.authorizedScopes() == null) {
            authorizedScopes = Set.of();
        } else {
            authorizedScopes = new HashSet<>(entity.authorizedScopes());
        }

        for (ClientAuthorizationTokenEntity tokenEntity : tokenEntities) {
            tokens.put(tokenEntity.gw2AccountId(), Token.fromEntity(tokenEntity));
        }

        return new ClientAuthorization(entity.accountId(), entity.clientRegistrationId(), entity.accountSub(), authorizedScopes, tokens);
    }

    public record Token(String gw2ApiSubtoken, Instant expirationTime) {

        public static Token fromEntity(ClientAuthorizationTokenEntity entity) {
            return new Token(entity.gw2ApiSubtoken(), entity.expirationTime());
        }
    }
}
