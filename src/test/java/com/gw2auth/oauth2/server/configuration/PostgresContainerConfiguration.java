package com.gw2auth.oauth2.server.configuration;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jdbc.repository.config.EnableJdbcRepositories;
import org.springframework.jdbc.datasource.SimpleDriverDataSource;
import org.testcontainers.containers.JdbcDatabaseContainer;
import org.testcontainers.containers.PostgreSQLContainerProvider;

import javax.sql.DataSource;

@TestConfiguration
@EnableJdbcRepositories("com.gw2auth.oauth2.server.repository")
public class PostgresContainerConfiguration {

    @Bean
    public JdbcDatabaseContainer<?> postgreSQLContainer() {
        final JdbcDatabaseContainer<?> container = new PostgreSQLContainerProvider().newInstance("13.4");
        container.start();

        return container;
    }

    @Bean
    public DataSource dataSource(JdbcDatabaseContainer<?> pg) {
        return new SimpleDriverDataSource(pg.getJdbcDriverInstance(), pg.getJdbcUrl(), pg.getUsername(), pg.getPassword());
    }
}
