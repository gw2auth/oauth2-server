package com.gw2auth.oauth2.server.configuration;

import com.gw2auth.oauth2.server.service.gw2.client.ChainedGw2ApiClient;
import com.gw2auth.oauth2.server.service.gw2.client.Gw2ApiClient;
import com.gw2auth.oauth2.server.service.gw2.client.MetricCollector;
import com.gw2auth.oauth2.server.service.gw2.client.RestOperationsGw2ApiClient;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;
import org.testcontainers.shaded.com.google.common.util.concurrent.MoreExecutors;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.ExecutorService;

@Configuration
public class Gw2ApiClientConfiguration {

    @Bean("gw2-rest-template")
    public RestTemplate gw2RestTemplate() {
        return new RestTemplate();
    }

    @Bean("gw2-rest-server")
    public MockRestServiceServer gw2RestServer(@Qualifier("gw2-rest-template") RestTemplate gw2RestTemplate) {
        return MockRestServiceServer.bindTo(gw2RestTemplate).build();
    }

    @Primary
    @Bean
    public Gw2ApiClient gw2ApiClient(@Qualifier("gw2-rest-template") RestTemplate gw2RestTemplate) {
        return new ChainedGw2ApiClient(List.of(new RestOperationsGw2ApiClient(gw2RestTemplate, MetricCollector.NONE)), Duration.ofMinutes(1L));
    }

    @Primary
    @Bean("gw2-api-client-executor-service")
    public ExecutorService gw2ApiClientExecutorService() {
        return MoreExecutors.newDirectExecutorService();
    }
}
