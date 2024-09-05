package com.gw2auth.oauth2.server.repository;

import org.springframework.data.repository.NoRepositoryBean;
import org.springframework.data.repository.Repository;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;

@NoRepositoryBean
@Retryable(
        exceptionExpression = "@cockroachExceptionClassifier.shouldRetry(#root)",
        maxAttempts = 5,
        backoff = @Backoff(delay = 500, multiplier = 1.5, maxDelay = 5000)
)
public interface BaseRepository<T> extends Repository<T, Void> {

    T save(T entity);
}
