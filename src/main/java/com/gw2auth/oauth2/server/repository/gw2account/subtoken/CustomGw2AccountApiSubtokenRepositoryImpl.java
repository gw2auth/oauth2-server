package com.gw2auth.oauth2.server.repository.gw2account.subtoken;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;
import org.springframework.stereotype.Component;

import java.sql.Timestamp;
import java.util.Collection;
import java.util.Map;

@Component
public class CustomGw2AccountApiSubtokenRepositoryImpl implements CustomGw2AccountApiSubtokenRepository {

    private static final String QUERY = """
    INSERT INTO gw2_account_api_subtokens
    (account_id, gw2_account_id, gw2_api_permissions_bit_set, gw2_api_subtoken, expiration_time)
    VALUES
    (:account_id, :gw2_account_id, :gw2_api_permissions_bit_set, :gw2_api_subtoken, :expiration_time)
    ON CONFLICT (account_id, gw2_account_id, gw2_api_permissions_bit_set) DO UPDATE SET
    gw2_api_subtoken = EXCLUDED.gw2_api_subtoken,
    expiration_time = EXCLUDED.expiration_time
    """;

    private final NamedParameterJdbcOperations namedParameterJdbcOperations;

    @Autowired
    public CustomGw2AccountApiSubtokenRepositoryImpl(NamedParameterJdbcOperations namedParameterJdbcOperations) {
        this.namedParameterJdbcOperations = namedParameterJdbcOperations;
    }

    @Override
    public void saveAll(Collection<Gw2AccountApiSubtokenEntity> entities) {
        final SqlParameterSource[] sqlParameterSources = new SqlParameterSource[entities.size()];
        int idx = 0;

        for (Gw2AccountApiSubtokenEntity entity : entities) {
            sqlParameterSources[idx++] = new MapSqlParameterSource(Map.of(
                    "account_id", entity.accountId(),
                    "gw2_account_id", entity.gw2AccountId(),
                    "gw2_api_permissions_bit_set", entity.gw2ApiPermissionsBitSet(),
                    "gw2_api_subtoken", entity.gw2ApiSubtoken(),
                    "expiration_time", Timestamp.from(entity.expirationTime())
            ));
        }

        this.namedParameterJdbcOperations.batchUpdate(QUERY, sqlParameterSources);
    }
}
