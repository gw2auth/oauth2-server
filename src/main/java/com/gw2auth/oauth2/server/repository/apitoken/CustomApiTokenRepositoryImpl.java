package com.gw2auth.oauth2.server.repository.apitoken;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Collection;
import java.util.Map;

@Component
public class CustomApiTokenRepositoryImpl implements CustomApiTokenRepository {

    private static final String QUERY = """
    UPDATE gw2_api_tokens
    SET last_valid_check_time = :last_valid_check_time,
    is_valid = :is_valid
    WHERE account_id = :account_id
    AND gw2_account_id = :gw2_account_id
    """;

    private final NamedParameterJdbcOperations namedParameterJdbcOperations;

    @Autowired
    public CustomApiTokenRepositoryImpl(NamedParameterJdbcOperations namedParameterJdbcOperations) {
        this.namedParameterJdbcOperations = namedParameterJdbcOperations;
    }

    @Transactional
    @Override
    public void updateApiTokensValid(Instant lastValidCheckTime, Collection<ApiTokenValidityUpdateEntity> updates) {
        final SqlParameterSource[] sqlParameterSources = new SqlParameterSource[updates.size()];
        int idx = 0;

        for (ApiTokenValidityUpdateEntity entity : updates) {
            sqlParameterSources[idx++] = new MapSqlParameterSource(Map.of(
                    "account_id", entity.accountId(),
                    "gw2_account_id", entity.gw2AccountId(),
                    "last_valid_check_time", Timestamp.from(lastValidCheckTime),
                    "is_valid", entity.isValid()
            ));
        }

        this.namedParameterJdbcOperations.batchUpdate(QUERY, sqlParameterSources);
    }
}
