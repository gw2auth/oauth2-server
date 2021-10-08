package com.gw2auth.oauth2.server.configuration;

import com.opentable.db.postgres.embedded.EmbeddedPostgres;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jdbc.repository.config.EnableJdbcRepositories;

import javax.sql.DataSource;
import java.io.IOException;

@TestConfiguration
@EnableJdbcRepositories("com.gw2auth.oauth2.server.repository")
public class EmbeddedPostgresConfiguration {

    @Bean
    public EmbeddedPostgres embeddedPostgres() throws IOException {
        return EmbeddedPostgres.builder().start();
    }

    @Bean
    public DataSource dataSource(EmbeddedPostgres pg) {
        return pg.getPostgresDatabase();
    }
}
