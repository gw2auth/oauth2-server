package com.gw2auth.oauth2.server.configuration;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.arn.Arn;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gw2auth.oauth2.server.service.gw2.client.*;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.metrics.web.client.MetricsRestTemplateCustomizer;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Configuration
public class Gw2ApiClientConfiguration {

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(3L);
    private static final Duration READ_TIMEOUT = Duration.ofSeconds(5L);
    private static final ClientConfiguration CLIENT_CONFIGURATION = new ClientConfiguration()
            .withConnectionTimeout((int) CONNECT_TIMEOUT.toMillis())
            .withClientExecutionTimeout((int) READ_TIMEOUT.toMillis());

    @Bean
    public Gw2ApiClient gw2ApiClient(MetricsRestTemplateCustomizer metricsRestTemplateCustomizer,
                                     ObjectMapper objectMapper,
                                     @Value("${com.gw2auth.gw2.client.aws-lambda-proxy.arns}") List<String> awsLambdaProxyARNs,
                                     @Value("${management.endpoint.prometheus.enabled:false}") boolean metricsEnabled,
                                     MeterRegistry meterRegistry) {

        final RestTemplate restTemplate = new RestTemplateBuilder()
                .rootUri("https://api.guildwars2.com")
                .setConnectTimeout(CONNECT_TIMEOUT)
                .setReadTimeout(READ_TIMEOUT)
                .customizers(metricsRestTemplateCustomizer)
                .build();

        final List<Gw2ApiClient> chain = new ArrayList<>(awsLambdaProxyARNs.size() + 1);
        chain.add(new InstrumentedGw2ApiClient(
                new RestOperationsGw2ApiClient(restTemplate),
                createMetricCollector(metricsEnabled, meterRegistry, "http.local")
        ));

        for (String awsLambdaProxyARN : awsLambdaProxyARNs) {
            final AWSLambda lambdaClient = createLambdaClientForARN(awsLambdaProxyARN);

            chain.add(new InstrumentedGw2ApiClient(
                    new AwsLambdaGw2ApiClient(lambdaClient, awsLambdaProxyARN, objectMapper),
                    createMetricCollector(metricsEnabled, meterRegistry, "lambda." + Arn.fromString(awsLambdaProxyARN).getRegion())
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

    private AWSLambda createLambdaClientForARN(String awsLambdaProxyARN) {
        final Regions region = Regions.fromName(Arn.fromString(awsLambdaProxyARN).getRegion());

        return AWSLambdaClientBuilder.standard()
                .withRegion(region)
                .withClientConfiguration(CLIENT_CONFIGURATION)
                .build();
    }

    @Bean("gw2-api-client-executor-service")
    public ExecutorService gw2ApiClientExecutorService() {
        return Executors.newCachedThreadPool();
    }
}
