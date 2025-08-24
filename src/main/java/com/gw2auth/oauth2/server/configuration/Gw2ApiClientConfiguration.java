package com.gw2auth.oauth2.server.configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gw2auth.oauth2.server.service.gw2.client.*;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;
import software.amazon.awssdk.arns.Arn;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.lambda.LambdaClient;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Configuration
public class Gw2ApiClientConfiguration {

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(3L);
    private static final Duration READ_TIMEOUT = Duration.ofSeconds(10L);

    @Bean
    public Gw2ApiClient gw2ApiClient(RestTemplateBuilder restTemplateBuilder,
                                     ObjectMapper objectMapper,
                                     @Value("${com.gw2auth.gw2.client.aws-lambda-proxy.arns}") List<String> awsLambdaProxyARNs,
                                     @Value("${management.endpoint.prometheus.enabled:false}") boolean metricsEnabled,
                                     MeterRegistry meterRegistry) {

        final RestTemplate restTemplate = restTemplateBuilder
                .rootUri("https://api.guildwars2.com")
                .connectTimeout(CONNECT_TIMEOUT)
                .readTimeout(READ_TIMEOUT)
                .build();

        final List<Gw2ApiClient> chain = new ArrayList<>(awsLambdaProxyARNs.size() + 1);
        chain.add(new InstrumentedGw2ApiClient(
                new RestOperationsGw2ApiClient(restTemplate),
                createMetricCollector(metricsEnabled, meterRegistry, "http.local")
        ));

        for (String awsLambdaProxyARN : awsLambdaProxyARNs) {
            final LambdaClient lambdaClient = createLambdaClientForARN(awsLambdaProxyARN);

            chain.add(new InstrumentedGw2ApiClient(
                    new AwsLambdaGw2ApiClient(
                            lambdaClient,
                            awsLambdaProxyARN,
                            objectMapper
                    ),
                    createMetricCollector(metricsEnabled, meterRegistry, "lambda." + Arn.fromString(awsLambdaProxyARN).region().orElseThrow())
            ));
        }

        return new InstrumentedGw2ApiClient(
                new ChainedGw2ApiClient(chain, Duration.ofMinutes(1L)),
                createMetricCollector(metricsEnabled, meterRegistry, "chain")
        );
    }

    private MetricCollector createMetricCollector(boolean enabled, MeterRegistry meterRegistry, String clientName) {
        if (!enabled) {
            return MetricCollector.NONE;
        }

        return new MicrometerMetricCollector(meterRegistry, "gw2_api_requests", clientName);
    }

    private LambdaClient createLambdaClientForARN(String awsLambdaProxyARN) {
        final Region region = Arn.fromString(awsLambdaProxyARN).region()
                .map(Region::of)
                .orElseThrow();

        return LambdaClient.builder()
                .region(region)
                .overrideConfiguration((config) -> config.apiCallTimeout(READ_TIMEOUT))
                .build();
    }

    @Bean("gw2-api-client-executor-service")
    public ExecutorService gw2ApiClientExecutorService() {
        return Executors.newVirtualThreadPerTaskExecutor();
    }
}
