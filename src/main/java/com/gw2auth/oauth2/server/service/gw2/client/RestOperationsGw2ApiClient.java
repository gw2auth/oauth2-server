package com.gw2auth.oauth2.server.service.gw2.client;

import com.fasterxml.jackson.core.type.TypeReference;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.client.RestOperations;
import org.springframework.web.util.UriComponentsBuilder;

public class RestOperationsGw2ApiClient implements Gw2ApiClient {

    private final RestOperations restOperations;

    public RestOperationsGw2ApiClient(RestOperations restOperations) {
        this.restOperations = restOperations;
    }

    @Override
    public <T> ResponseEntity<T> get(String path, MultiValueMap<String, String> query, MultiValueMap<String, String> headers, TypeReference<T> typeReference) {
        ResponseEntity<T> response;
        try {
            response = this.restOperations.exchange(
                    UriComponentsBuilder.fromPath(path).queryParams(query).toUriString(),
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    ParameterizedTypeReference.forType(typeReference.getType())
            );
        } catch (RestClientResponseException e) {
            response = ResponseEntity.status(e.getRawStatusCode()).headers(e.getResponseHeaders()).build();
        }

        return response;
    }
}
