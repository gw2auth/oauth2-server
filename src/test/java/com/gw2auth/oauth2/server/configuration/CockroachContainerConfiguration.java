package com.gw2auth.oauth2.server.configuration;

import org.springframework.boot.autoconfigure.flyway.FlywayDataSource;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.data.jdbc.repository.config.EnableJdbcRepositories;
import org.springframework.jdbc.datasource.SimpleDriverDataSource;
import org.testcontainers.containers.CockroachContainerProvider;
import org.testcontainers.containers.JdbcDatabaseContainer;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.Statement;

@TestConfiguration
@EnableJdbcRepositories("com.gw2auth.oauth2.server.repository")
public class CockroachContainerConfiguration {

    @Bean
    public JdbcDatabaseContainer<?> cockroachDBContainer() throws Exception {
        final JdbcDatabaseContainer<?> container = new CockroachContainerProvider().newInstance("v22.1.7");
        container.start();

        try (Connection conn = new SimpleDriverDataSource(container.getJdbcDriverInstance(), container.getJdbcUrl(), container.getUsername(), container.getPassword()).getConnection()) {
            try (Statement stmt = conn.createStatement()) {
                stmt.execute("CREATE USER flyway");
                stmt.execute("CREATE USER gw2auth_app");
            }
        }

        return container;
    }

    @Bean
    @Primary
    public DataSource dataSource(JdbcDatabaseContainer<?> pg) {
        return new SimpleDriverDataSource(pg.getJdbcDriverInstance(), pg.getJdbcUrl(), "gw2auth_app", "");
    }

    @Bean
    @FlywayDataSource
    public DataSource flywayDataSource(JdbcDatabaseContainer<?> pg) {
        return new SimpleDriverDataSource(pg.getJdbcDriverInstance(), pg.getJdbcUrl(), "flyway", "");
    }
}
