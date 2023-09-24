package com.gw2auth.oauth2.server.service.gw2.client;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.lambda.model.InvocationType;
import software.amazon.awssdk.services.lambda.model.InvokeRequest;
import software.amazon.awssdk.services.lambda.model.InvokeResponse;
import software.amazon.awssdk.services.lambda.model.LogType;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;

public class AwsLambdaGw2ApiClient implements Gw2ApiClient {

    private final MinimalLambdaClient lambda;
    private final String functionName;
    private final ObjectMapper mapper;

    public AwsLambdaGw2ApiClient(MinimalLambdaClient lambda, String functionName, ObjectMapper mapper) {
        this.lambda = lambda;
        this.functionName = functionName;
        this.mapper = mapper;
    }

    @Override
    public ResponseEntity<Resource> get(String path, MultiValueMap<String, String> query, MultiValueMap<String, String> headers) {
        return get(null, path, query, headers);
    }

    @Override
    public ResponseEntity<Resource> get(Duration timeout, String path, MultiValueMap<String, String> query, MultiValueMap<String, String> headers) {
        try {
            return get(buildInvokeRequest(timeout, buildPayloadJson(path, query, headers)));
        } catch (Exception e) {
            throw new RuntimeException("unexpected Exception during AwsLambdaGw2ApiClient.get", e);
        }
    }

    private ResponseEntity<Resource> get(InvokeRequest invokeRequest) throws Exception {
        final InvokeResponse lambdaResponse = this.lambda.invoke(invokeRequest);

        if (lambdaResponse.functionError() != null) {
            throw new RuntimeException(lambdaResponse.functionError());
        }

        final int statusCode;
        final HttpHeaders responseHeaders;
        final byte[] body;

        try (InputStream in = lambdaResponse.payload().asInputStream()) {
            final LambdaResponsePayload gw2Response = this.mapper.readValue(in, LambdaResponsePayload.class);

            statusCode = gw2Response.statusCode();
            responseHeaders = new HttpHeaders();
            gw2Response.headers().forEach(responseHeaders::add);

            if (gw2Response.isBase64Encoded()) {
                body = Base64.getDecoder().decode(gw2Response.body());
            } else {
                body = gw2Response.body().getBytes(StandardCharsets.UTF_8);
            }
        }

        return ResponseEntity
                .status(statusCode)
                .headers(responseHeaders)
                .body(new ByteArrayResource(body));
    }

    private byte[] buildPayloadJson(String path, MultiValueMap<String, String> query, MultiValueMap<String, String> headers) {
        final byte[] payloadJson;
        try {
            payloadJson = this.mapper.writeValueAsBytes(new LambdaRequestPayload(path, query.toSingleValueMap(), headers.toSingleValueMap()));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }

        return payloadJson;
    }

    private InvokeRequest buildInvokeRequest(Duration timeout, byte[] payload) {
        InvokeRequest.Builder builder = InvokeRequest.builder()
                .invocationType(InvocationType.REQUEST_RESPONSE)
                .logType(LogType.NONE)
                .functionName(this.functionName)
                .payload(SdkBytes.fromByteArray(payload));

        if (timeout != null) {
            builder = builder.overrideConfiguration((config) -> config.apiCallTimeout(timeout));
        }

        return builder.build();
    }

    record LambdaRequestPayload(@JsonProperty("path") String path, @JsonProperty("query") Map<String, String> query, @JsonProperty("headers") Map<String, String> headers) {}
    record LambdaResponsePayload(@JsonProperty("isBase64Encoded") boolean isBase64Encoded, @JsonProperty("statusCode") int statusCode, @JsonProperty("headers") Map<String, String> headers, @JsonProperty("body") String body) {}

    public interface MinimalLambdaClient {

        InvokeResponse invoke(InvokeRequest request);
    }
}
