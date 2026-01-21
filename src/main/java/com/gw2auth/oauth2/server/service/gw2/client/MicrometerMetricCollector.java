package com.gw2auth.oauth2.server.service.gw2.client;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.binder.http.Outcome;
import org.jspecify.annotations.Nullable;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class MicrometerMetricCollector implements MetricCollector {

    private final MeterRegistry meterRegistry;
    private final String metricName;
    private final String clientName;

    public MicrometerMetricCollector(MeterRegistry meterRegistry, String metricName, String clientName) {
        this.meterRegistry = meterRegistry;
        this.metricName = metricName;
        this.clientName = clientName;
    }

    @Override
    public void collectMetrics(String requestPath, MultiValueMap<String, String> requestQuery, HttpHeaders requestHeaders, ResponseEntity<Resource> response, Duration duration) {
        collectMetrics(requestPath, requestQuery, requestHeaders, response, null, duration);
    }

    @Override
    public void collectMetrics(String requestPath, MultiValueMap<String, String> requestQuery, HttpHeaders requestHeaders, Exception exc, Duration duration) {
        collectMetrics(requestPath, requestQuery, requestHeaders, null, exc, duration);
    }

    private void collectMetrics(String requestPath, MultiValueMap<String, String> requestQuery, HttpHeaders requestHeaders, @Nullable ResponseEntity<Resource> response, @Nullable Exception exc, Duration duration) {
        this.meterRegistry.timer(this.metricName, createTags(requestPath, requestQuery, requestHeaders, response, exc)).record(duration);
    }

    private Collection<Tag> createTags(String requestPath, MultiValueMap<String, String> requestQuery, HttpHeaders requestHeaders, @Nullable ResponseEntity<Resource> response, @Nullable Exception exc) {
        return List.of(
                Tag.of("client.name", this.clientName),
                Tag.of("method", HttpMethod.GET.name()),
                Tag.of("uri", buildRequestUriTemplate(requestPath, requestQuery)),
                Tag.of("status", response == null ? exc.getClass().getSimpleName() : Integer.toString(response.getStatusCode().value())),
                Tag.of("outcome", response == null ? "UNKNOWN" : Outcome.forStatus(response.getStatusCode().value()).name())
        );
    }

    private String buildRequestUriTemplate(String requestPath, MultiValueMap<String, String> requestQuery) {
        if (requestQuery.isEmpty()) {
            return requestPath;
        }

        return requestPath + "?" + requestQuery.keySet().stream()
                .sorted()
                .map((v) -> URLDecoder.decode(v, StandardCharsets.US_ASCII) + "={value}")
                .collect(Collectors.joining("&"));
    }
}
