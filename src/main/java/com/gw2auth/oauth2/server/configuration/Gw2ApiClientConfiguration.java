package com.gw2auth.oauth2.server.configuration;

import com.gw2auth.oauth2.server.service.gw2.client.*;
import com.gw2auth.oauth2.server.util.AllowAlternateDomainX509TrustManager;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.net.ssl.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Function;

@Configuration
public class Gw2ApiClientConfiguration {

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(3L);
    private static final Duration READ_TIMEOUT = Duration.ofSeconds(10L);

    @Bean(destroyMethod = "close")
    public Gw2ApiClient gw2ApiClient(RestTemplateBuilder restTemplateBuilder,
                                     @Value("${com.gw2auth.gw2.client.proxy-hosts}") List<String> proxyHosts,
                                     @Value("${management.endpoint.prometheus.enabled:false}") boolean metricsEnabled,
                                     MeterRegistry meterRegistry) throws Exception {

        final Gw2ApiClient localApiClient = new InstrumentedGw2ApiClient(
                new RestOperationsGw2ApiClient(
                        restTemplateBuilder
                                .rootUri("https://api.guildwars2.com")
                                .connectTimeout(CONNECT_TIMEOUT)
                                .readTimeout(READ_TIMEOUT)
                                .build()
                ),
                createMetricCollector(metricsEnabled, meterRegistry, "http.local")
        );

        final List<Gw2ApiClient> chain = new ArrayList<>(proxyHosts.size() + 1);
        chain.add(localApiClient);

        if (!proxyHosts.isEmpty()) {
            System.setProperty("jdk.httpclient.allowRestrictedHeaders", "host");

            final Function<HttpRequest.Builder, HttpRequest> requestFinalizer = (builder) -> builder
                    .setHeader("Host", "api.guildwars2.com")
                    .build();

            for (String proxyHost : proxyHosts) {
                final TrustManager[] trustAlternateDomain = new TrustManager[]{new AllowAlternateDomainX509TrustManager(proxyHost)};
                final SSLContext sslContext = SSLContext.getInstance("SSL");
                sslContext.init(null, trustAlternateDomain, new SecureRandom());

                final HttpClient httpClient = HttpClient.newBuilder()
                        .sslContext(sslContext)
                        .version(HttpClient.Version.HTTP_1_1)
                        .connectTimeout(CONNECT_TIMEOUT)
                        .build();

                chain.add(new InstrumentedGw2ApiClient(
                        new HttpClientGw2ApiClient(httpClient, "https://" + proxyHost, requestFinalizer),
                        createMetricCollector(metricsEnabled, meterRegistry, "http." + proxyHost)
                ));
            }
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

    @Bean("gw2-api-client-executor-service")
    public ExecutorService gw2ApiClientExecutorService() {
        return Executors.newVirtualThreadPerTaskExecutor();
    }
}
