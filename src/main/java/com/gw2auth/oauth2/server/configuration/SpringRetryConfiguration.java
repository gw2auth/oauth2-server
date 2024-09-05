package com.gw2auth.oauth2.server.configuration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.NestedExceptionUtils;
import org.springframework.retry.annotation.EnableRetry;

import java.sql.SQLException;

@Configuration
@EnableRetry
public class SpringRetryConfiguration {

    @Bean
    public CockroachExceptionClassifier cockroachExceptionClassifier() {
        return new CockroachExceptionClassifier();
    }

    public static class CockroachExceptionClassifier {

        private static final Logger LOG = LoggerFactory.getLogger(CockroachExceptionClassifier.class);
        private static final String RETRY_SQL_STATE = "40001";

        private CockroachExceptionClassifier() {}

        public boolean shouldRetry(Throwable exc) {
            if (exc == null) {
                return false;
            }

            if (exc instanceof SQLException sqlExc) {
                return shouldRetry(sqlExc);
            } else {
                final Throwable cause = NestedExceptionUtils.getMostSpecificCause(exc);
                if (cause instanceof SQLException sqlExc) {
                    return shouldRetry(sqlExc);
                }
            }

            return false;
        }

        public boolean shouldRetry(SQLException exc) {
            if (exc != null && exc.getSQLState().equals(RETRY_SQL_STATE)) {
                LOG.warn("transient SQLException detected", exc);
                return true;
            }

            return false;
        }
    }
}
