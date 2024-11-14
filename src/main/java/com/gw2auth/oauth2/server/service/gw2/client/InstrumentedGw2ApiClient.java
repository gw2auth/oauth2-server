package com.gw2auth.oauth2.server.service.gw2.client;

import org.jspecify.annotations.Nullable;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;

import java.time.Duration;
import java.time.Instant;

public class InstrumentedGw2ApiClient implements Gw2ApiClient {

    private final Gw2ApiClient client;
    private final MetricCollector metricCollector;

    public InstrumentedGw2ApiClient(Gw2ApiClient client, MetricCollector metricCollector) {
        this.client = client;
        this.metricCollector = metricCollector;
    }

    @Override
    public ResponseEntity<Resource> get(String path, MultiValueMap<String, String> query, MultiValueMap<String, String> headers) {
        return getWithMetrics(null, path, query, headers);
    }

    @Override
    public ResponseEntity<Resource> get(@Nullable Duration timeout, String path, MultiValueMap<String, String> query, MultiValueMap<String, String> headers) {
        return getWithMetrics(timeout, path, query, headers);
    }

    private ResponseEntity<Resource> getWithMetrics(@Nullable Duration timeout, String path, MultiValueMap<String, String> query, MultiValueMap<String, String> headers) {
        final Instant start = Instant.now();
        try {
            final ResponseEntity<Resource> response;
            if (timeout == null) {
                response = this.client.get(path, query, headers);
            } else {
                response = this.client.get(timeout, path, query, headers);
            }

            this.metricCollector.collectMetrics(path, query, headers, response, Duration.between(start, Instant.now()));
            return response;
        } catch (Exception e) {
            this.metricCollector.collectMetrics(path, query, headers, e, Duration.between(start, Instant.now()));
            throw e;
        }
    }
}
