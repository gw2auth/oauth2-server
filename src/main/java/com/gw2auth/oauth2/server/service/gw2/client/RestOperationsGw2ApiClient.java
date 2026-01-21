package com.gw2auth.oauth2.server.service.gw2.client;

import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.*;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class RestOperationsGw2ApiClient implements Gw2ApiClient {

    private final RestOperations restOperations;

    public RestOperationsGw2ApiClient(RestOperations restOperations) {
        this.restOperations = restOperations;
    }

    @Override
    public ResponseEntity<Resource> get(String path, MultiValueMap<String, String> query, HttpHeaders headers) {
        return getInternal(path, query, headers);
    }

    @Override
    public ResponseEntity<Resource> get(Duration timeout, String path, MultiValueMap<String, String> query, HttpHeaders headers) {
        return getInternal(path, query, headers);
    }

    private ResponseEntity<Resource> getInternal(String path, MultiValueMap<String, String> query, HttpHeaders headers) {
        final UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromPath(path);
        final Map<String, String> params = new HashMap<>(query.size());
        int i = 0;
        String variableName;

        for (Map.Entry<String, List<String>> entry : query.entrySet()) {
            for (String value : entry.getValue()) {
                variableName = "_" + (i++);

                uriComponentsBuilder.queryParam(entry.getKey(), "{" + variableName + "}");
                params.put(variableName, value);
            }
        }

        ResponseEntity<Resource> response;
        try {
            response = this.restOperations.exchange(
                    uriComponentsBuilder.build().toUriString(),
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    Resource.class,
                    params
            );
        } catch (ResourceAccessException e) {
            // thrown if a clientside connection timeout passed (read/connect)
            response = ResponseEntity.status(HttpStatus.REQUEST_TIMEOUT).body(null);
        } catch (RestClientResponseException e) {
            response = ResponseEntity.status(e.getStatusCode())
                    .headers(e.getResponseHeaders())
                    .body(new ByteArrayResource(e.getResponseBodyAsByteArray()));
        }

        return response;
    }

    @Override
    public void close() throws Exception {
        // noop
    }
}
