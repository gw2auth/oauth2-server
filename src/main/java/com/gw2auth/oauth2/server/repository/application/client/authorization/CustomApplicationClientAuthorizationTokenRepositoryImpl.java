package com.gw2auth.oauth2.server.repository.application.client.authorization;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.Map;

@Component
public class CustomApplicationClientAuthorizationTokenRepositoryImpl implements CustomApplicationClientAuthorizationTokenRepository {

    private static final String QUERY = """
    INSERT INTO application_client_authorization_gw2_accounts
    (application_client_authorization_id, account_id, gw2_account_id)
    VALUES
    (:application_client_authorization_id, :account_id, :gw2_account_id)
    ON CONFLICT (application_client_authorization_id, gw2_account_id) DO NOTHING
    """;

    private final NamedParameterJdbcOperations namedParameterJdbcOperations;

    @Autowired
    public CustomApplicationClientAuthorizationTokenRepositoryImpl(NamedParameterJdbcOperations namedParameterJdbcOperations) {
        this.namedParameterJdbcOperations = namedParameterJdbcOperations;
    }

    @Override
    @Transactional
    public void saveAll(Collection<ApplicationClientAuthorizationTokenEntity> entities) {
        final SqlParameterSource[] sqlParameterSources = new SqlParameterSource[entities.size()];
        int idx = 0;

        for (ApplicationClientAuthorizationTokenEntity entity : entities) {
            sqlParameterSources[idx++] = new MapSqlParameterSource(Map.of(
                    "application_client_authorization_id", entity.applicationClientAuthorizationId(),
                    "account_id", entity.accountId(),
                    "gw2_account_id", entity.gw2AccountId()
            ));
        }

        this.namedParameterJdbcOperations.batchUpdate(QUERY, sqlParameterSources);
    }
}
