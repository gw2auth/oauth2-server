package com.gw2auth.oauth2.server.repository;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.NestedExceptionUtils;
import org.springframework.data.repository.NoRepositoryBean;
import org.springframework.data.repository.Repository;
import org.springframework.resilience.annotation.Retryable;
import org.springframework.resilience.retry.MethodRetryPredicate;

import java.lang.reflect.Method;
import java.sql.SQLException;

@NoRepositoryBean
@Retryable(
        predicate = BaseRepository.CockroachMethodRetryPredicate.class,
        maxRetries = 4L,
        delay = 500L,
        multiplier = 1.5,
        maxDelay = 5000L
)
public interface BaseRepository<T> extends Repository<T, Void> {

    T save(T entity);

    final class CockroachMethodRetryPredicate implements MethodRetryPredicate {

        private static final Logger LOG = LoggerFactory.getLogger(CockroachMethodRetryPredicate.class);
        private static final String RETRY_SQL_STATE = "40001";

        @Override
        public boolean shouldRetry(Method method, Throwable throwable) {
            return shouldRetry(throwable);
        }

        private boolean shouldRetry(Throwable exc) {
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

        private boolean shouldRetry(SQLException exc) {
            if (exc != null && exc.getSQLState().equals(RETRY_SQL_STATE)) {
                LOG.warn("transient SQLException detected", exc);
                return true;
            }

            return false;
        }
    }
}
