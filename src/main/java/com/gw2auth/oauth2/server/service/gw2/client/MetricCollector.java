package com.gw2auth.oauth2.server.service.gw2.client;

import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;

import java.time.Duration;

public interface MetricCollector {

    MetricCollector NONE = new MetricCollector() {
        @Override
        public void collectMetrics(String requestPath, MultiValueMap<String, String> requestQuery, MultiValueMap<String, String> requestHeaders, ResponseEntity<Resource> response, Duration duration) {
            // no-op
        }

        @Override
        public void collectMetrics(String requestPath, MultiValueMap<String, String> requestQuery, MultiValueMap<String, String> requestHeaders, Exception exc, Duration duration) {
            // no-op
        }
    };

    void collectMetrics(String requestPath, MultiValueMap<String, String> requestQuery, MultiValueMap<String, String> requestHeaders, ResponseEntity<Resource> response, Duration duration);
    void collectMetrics(String requestPath, MultiValueMap<String, String> requestQuery, MultiValueMap<String, String> requestHeaders, Exception exc, Duration duration);
}
