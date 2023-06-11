package com.gw2auth.oauth2.server.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.testcontainers.shaded.com.google.common.util.concurrent.MoreExecutors;

import java.util.concurrent.ExecutorService;

@Configuration
public class AsyncTasksConfiguration {

    @Primary
    @Bean("async-tasks-executor-service")
    public ExecutorService asyncTasksExecutorService() {
        return MoreExecutors.newDirectExecutorService();
    }
}
