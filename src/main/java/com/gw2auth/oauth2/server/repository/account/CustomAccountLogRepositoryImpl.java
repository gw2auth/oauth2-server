package com.gw2auth.oauth2.server.repository.account;

import org.json.JSONObject;
import org.postgresql.util.PGobject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.converter.Converter;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcOperations;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;
import org.springframework.stereotype.Component;

import java.sql.Timestamp;
import java.util.Collection;
import java.util.Map;
import java.util.Objects;

@Component
public class CustomAccountLogRepositoryImpl implements CustomAccountLogRepository {

    private static final String INSERT_QUERY = """
    INSERT INTO account_logs
    (id, account_id, timestamp, message, fields, persistent)
    VALUES
    (:id, :account_id, :timestamp, :message, :fields, :persistent)
    """;

    private final NamedParameterJdbcOperations namedParameterJdbcOperations;
    private final Converter<JSONObject, PGobject> jsonWritingConverter;

    @Autowired
    public CustomAccountLogRepositoryImpl(NamedParameterJdbcOperations namedParameterJdbcOperations, Converter<JSONObject, PGobject> jsonWritingConverter) {
        this.namedParameterJdbcOperations = namedParameterJdbcOperations;
        this.jsonWritingConverter = jsonWritingConverter;
    }

    @Override
    public void saveAll(Collection<AccountLogEntity> entities) {
        final SqlParameterSource[] sqlParameterSources = new SqlParameterSource[entities.size()];
        int idx = 0;

        for (AccountLogEntity entity : entities) {
            sqlParameterSources[idx++] = new MapSqlParameterSource(Map.of(
                    "id", entity.id(),
                    "account_id", entity.accountId(),
                    "timestamp", Timestamp.from(entity.timestamp()),
                    "message", entity.message(),
                    "fields", Objects.requireNonNull(this.jsonWritingConverter.convert(entity.fields())),
                    "persistent", entity.persistent()
            ));
        }

        this.namedParameterJdbcOperations.batchUpdate(INSERT_QUERY, sqlParameterSources);
    }
}
