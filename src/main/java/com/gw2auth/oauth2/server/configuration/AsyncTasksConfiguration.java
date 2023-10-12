package com.gw2auth.oauth2.server.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Configuration
public class AsyncTasksConfiguration {

    @Bean("async-tasks-executor-service")
    public ExecutorService asyncTasksExecutorService() {
        return Executors.newVirtualThreadPerTaskExecutor();
    }
}
