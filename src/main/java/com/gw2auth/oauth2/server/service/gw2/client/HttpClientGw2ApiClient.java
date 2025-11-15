package com.gw2auth.oauth2.server.service.gw2.client;

import org.jspecify.annotations.Nullable;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.*;
import org.springframework.http.HttpHeaders;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.net.http.*;
import java.net.http.HttpRequest;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

public class HttpClientGw2ApiClient implements Gw2ApiClient, AutoCloseable {

    private final HttpClient httpClient;
    private final String rootUri;
    private final Function<HttpRequest.Builder, HttpRequest> requestFinalizer;

    public HttpClientGw2ApiClient(HttpClient httpClient, String rootUri, @Nullable Function<HttpRequest.Builder, HttpRequest> requestFinalizer) {
        this.httpClient = Objects.requireNonNull(httpClient);
        this.rootUri = Objects.requireNonNull(rootUri);

        if (requestFinalizer == null) {
            this.requestFinalizer = HttpRequest.Builder::build;
        } else {
            this.requestFinalizer = requestFinalizer;
        }
    }

    public HttpClientGw2ApiClient(HttpClient httpClient, String rootUri) {
        this(httpClient, rootUri, null);
    }

    @Override
    public ResponseEntity<Resource> get(String path, MultiValueMap<String, String> query, MultiValueMap<String, String> headers) {
        return getInternal(path, query, headers);
    }

    @Override
    public ResponseEntity<Resource> get(Duration timeout, String path, MultiValueMap<String, String> query, MultiValueMap<String, String> headers) {
        return getInternal(path, query, headers);
    }

    private ResponseEntity<Resource> getInternal(String path, MultiValueMap<String, String> query, MultiValueMap<String, String> headers) {
        final HttpRequest request = buildRequest(path, query, headers);
        final HttpResponse<byte[]> response;
        try {
            response = this.httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
        } catch (HttpTimeoutException e) {
            return ResponseEntity.status(HttpStatus.REQUEST_TIMEOUT).body(null);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }

        final HttpHeaders responseHeaders = new HttpHeaders();
        response.headers().map().forEach(responseHeaders::addAll);

        return ResponseEntity
                .status(response.statusCode())
                .headers(responseHeaders)
                .body(new ByteArrayResource(response.body()));
    }

    private HttpRequest buildRequest(String path, MultiValueMap<String, String> query, MultiValueMap<String, String> headers) {
        final HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .GET()
                .uri(buildRequestURI(path, query));

        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            for (String value : entry.getValue()) {
                requestBuilder.header(entry.getKey(), value);
            }
        }

        return this.requestFinalizer.apply(requestBuilder);
    }

    private URI buildRequestURI(String path, MultiValueMap<String, String> query) {
        final UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUriString(this.rootUri + path);
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

        return uriComponentsBuilder.build(params);
    }

    @Override
    public void close() {
        this.httpClient.close();
    }

    @Override
    public String toString() {
        return String.format("%s[%s]", getClass().getSimpleName(), this.rootUri);
    }
}
