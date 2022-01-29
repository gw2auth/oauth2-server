package com.gw2auth.oauth2.server.repository.client.authorization;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.Map;

@Component
public class CustomClientAuthorizationTokenRepositoryImpl implements CustomClientAuthorizationTokenRepository {

    private static final String QUERY = """
    INSERT INTO client_authorization_tokens
    (account_id, client_authorization_id, gw2_account_id)
    VALUES
    (:account_id, :client_authorization_id, :gw2_account_id)
    ON CONFLICT DO NOTHING
    """;

    private final NamedParameterJdbcOperations namedParameterJdbcOperations;

    @Autowired
    public CustomClientAuthorizationTokenRepositoryImpl(NamedParameterJdbcOperations namedParameterJdbcOperations) {
        this.namedParameterJdbcOperations = namedParameterJdbcOperations;
    }

    @Override
    @Transactional
    public void saveAll(Collection<ClientAuthorizationTokenEntity> entities) {
        final SqlParameterSource[] sqlParameterSources = new SqlParameterSource[entities.size()];
        int idx = 0;

        for (ClientAuthorizationTokenEntity entity : entities) {
            sqlParameterSources[idx++] = new MapSqlParameterSource(Map.of(
                    "account_id", entity.accountId(),
                    "client_authorization_id", entity.clientAuthorizationId(),
                    "gw2_account_id", entity.gw2AccountId()
            ));
        }

        this.namedParameterJdbcOperations.batchUpdate(QUERY, sqlParameterSources);
    }
}
