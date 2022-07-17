package com.gw2auth.oauth2.server;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.flyway.FlywayDataSource;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Component
public class TruncateTablesExtension implements AfterEachCallback {

    private final DataSource dataSource;
    private final String schema;
    private final Set<String> excludeTableNames;

    public TruncateTablesExtension(DataSource dataSource, String schema, Set<String> excludeTableNames) {
        this.dataSource = dataSource;
        this.schema = schema;
        this.excludeTableNames = excludeTableNames;
    }

    @Autowired
    public TruncateTablesExtension(@FlywayDataSource DataSource dataSource) {
        this(dataSource, "public", Set.of("flyway_schema_history"));
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        try (Connection conn = this.dataSource.getConnection()) {
            final List<String> tableNames = new ArrayList<>();

            try (PreparedStatement pstmt = conn.prepareStatement("SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = ?")) {
                pstmt.setString(1, this.schema);

                try (ResultSet rs = pstmt.executeQuery()) {
                    while (rs.next()) {
                        tableNames.add(rs.getString(1));
                    }
                }
            }

            try (Statement stmt = conn.createStatement()) {
                for (String tableName : tableNames) {
                    if (!this.excludeTableNames.contains(tableName)) {
                        stmt.executeUpdate(String.format("TRUNCATE TABLE \"%s\".\"%s\" CASCADE", this.schema, tableName));
                    }
                }
            }
        }
    }
}
