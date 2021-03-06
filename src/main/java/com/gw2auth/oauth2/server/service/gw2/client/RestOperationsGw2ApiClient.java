package com.gw2auth.oauth2.server.service.gw2.client;

import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
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
    public ResponseEntity<Resource> get(String path, MultiValueMap<String, String> query, MultiValueMap<String, String> headers) {
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
        } catch (RestClientResponseException e) {
            response = ResponseEntity.status(e.getRawStatusCode())
                    .headers(e.getResponseHeaders())
                    .body(new ByteArrayResource(e.getResponseBodyAsByteArray()));
        }

        return response;
    }

    @Override
    public ResponseEntity<Resource> get(Duration timeout, String path, MultiValueMap<String, String> query, MultiValueMap<String, String> headers) {
        return get(path, query, headers);
    }
}
