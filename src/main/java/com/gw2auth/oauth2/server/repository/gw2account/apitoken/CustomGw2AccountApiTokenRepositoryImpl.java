package com.gw2auth.oauth2.server.repository.gw2account.apitoken;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.*;

@Component
public class CustomGw2AccountApiTokenRepositoryImpl implements CustomGw2AccountApiTokenRepository {

    private static final String QUERY_VALID = """
    UPDATE gw2_account_api_tokens
    SET last_valid_time = :last_valid_check_time, last_valid_check_time = :last_valid_check_time
    WHERE account_id = :account_id
    AND gw2_account_id = :gw2_account_id
    """;

    private static final String QUERY_INVALID = """
    UPDATE gw2_account_api_tokens
    SET last_valid_check_time = :last_valid_check_time
    WHERE account_id = :account_id
    AND gw2_account_id = :gw2_account_id
    """;

    private final NamedParameterJdbcOperations namedParameterJdbcOperations;

    @Autowired
    public CustomGw2AccountApiTokenRepositoryImpl(NamedParameterJdbcOperations namedParameterJdbcOperations) {
        this.namedParameterJdbcOperations = namedParameterJdbcOperations;
    }

    @Transactional
    @Override
    public void updateApiTokensValid(Instant lastValidCheckTime, Collection<Gw2AccountApiTokenValidUpdateEntity> updates) {
        final List<SqlParameterSource> sqlParameterSourcesValid = new ArrayList<>();
        final List<SqlParameterSource> sqlParameterSourcesInvalid = new ArrayList<>();

        for (Gw2AccountApiTokenValidUpdateEntity entity : updates) {
            final SqlParameterSource sqlParameterSource = new MapSqlParameterSource(Map.of(
                    "account_id", entity.accountId(),
                    "gw2_account_id", entity.gw2AccountId(),
                    "last_valid_check_time", Timestamp.from(lastValidCheckTime)
            ));

            if (entity.isValid()) {
                sqlParameterSourcesValid.add(sqlParameterSource);
            } else {
                sqlParameterSourcesInvalid.add(sqlParameterSource);
            }
        }

        if (!sqlParameterSourcesValid.isEmpty()) {
            this.namedParameterJdbcOperations.batchUpdate(QUERY_VALID, sqlParameterSourcesValid.toArray(SqlParameterSource[]::new));
        }

        if (!sqlParameterSourcesInvalid.isEmpty()) {
            this.namedParameterJdbcOperations.batchUpdate(QUERY_INVALID, sqlParameterSourcesInvalid.toArray(SqlParameterSource[]::new));
        }
    }
}
