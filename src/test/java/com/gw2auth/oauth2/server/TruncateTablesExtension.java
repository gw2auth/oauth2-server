package com.gw2auth.oauth2.server;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;

@Component
public class TruncateTablesExtension implements AfterEachCallback {

    private final JdbcOperations jdbcOperations;
    private final String schema;
    private final Set<String> excludeTableNames;

    public TruncateTablesExtension(JdbcOperations jdbcOperations, String schema, Set<String> excludeTableNames) {
        this.jdbcOperations = jdbcOperations;
        this.schema = schema;
        this.excludeTableNames = excludeTableNames;
    }

    @Autowired
    public TruncateTablesExtension(JdbcOperations jdbcOperations) {
        this(jdbcOperations, "public", Set.of("flyway_schema_history"));
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        final List<String> tableNames = this.jdbcOperations.query("SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = ?", (rs, rowNum) -> rs.getString(1), this.schema);

        for (String tableName : tableNames) {
            if (!this.excludeTableNames.contains(tableName)) {
                this.jdbcOperations.update(String.format("TRUNCATE TABLE \"%s\".\"%s\" CASCADE", this.schema, tableName));
            }
        }
    }
}
