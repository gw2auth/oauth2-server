package com.gw2auth.oauth2.server.service.gw2.client;

import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.model.*;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.util.ByteBufferBackedInputStream;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class AwsLambdaGw2ApiClient implements Gw2ApiClient {

    private final AWSLambda awsLambda;
    private final String functionName;
    private final ObjectMapper mapper;

    public AwsLambdaGw2ApiClient(AWSLambda awsLambda, String functionName, ObjectMapper mapper) {
        this.awsLambda = awsLambda;
        this.functionName = functionName;
        this.mapper = mapper;
    }

    @Override
    public <T> ResponseEntity<T> get(String path, MultiValueMap<String, String> query, MultiValueMap<String, String> headers, TypeReference<T> typeReference) {
        return get(buildInvokeRequest(null, buildPayloadJson(path, query, headers)), typeReference);
    }

    @Override
    public <T> ResponseEntity<T> get(long timeout, TimeUnit timeUnit, String path, MultiValueMap<String, String> query, MultiValueMap<String, String> headers, TypeReference<T> typeReference) {
        return get(buildInvokeRequest(Duration.ofNanos(timeUnit.toNanos(timeout)),  buildPayloadJson(path, query, headers)), typeReference);
    }

    private <T> ResponseEntity<T> get(InvokeRequest invokeRequest, TypeReference<T> typeReference) {
        final InvokeResult result = this.awsLambda.invoke(invokeRequest);

        if (result.getFunctionError() != null) {
            throw new AWSLambdaException(result.getFunctionError());
        }

        final int statusCode;
        final HttpHeaders responseHeaders;
        final T body;

        try (InputStream in = new ByteBufferBackedInputStream(result.getPayload())) {
            final LambdaResponsePayload response = this.mapper.readValue(in, LambdaResponsePayload.class);

            statusCode = response.statusCode();
            responseHeaders = new HttpHeaders();
            response.headers().forEach(responseHeaders::add);

            if (response.isBase64Encoded()) {
                body = this.mapper.readValue(Base64.getDecoder().decode(response.body()), typeReference);
            } else {
                body = this.mapper.readValue(response.body(), typeReference);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return ResponseEntity
                .status(statusCode)
                .headers(responseHeaders)
                .body(body);
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
        final InvokeRequest invokeRequest = new InvokeRequest()
                .withInvocationType(InvocationType.RequestResponse)
                .withLogType(LogType.None)
                .withFunctionName(this.functionName)
                .withPayload(ByteBuffer.wrap(payload));

        if (timeout != null) {
            invokeRequest.setSdkClientExecutionTimeout((int) timeout.toMillis());
        }

        return invokeRequest;
    }

    record LambdaRequestPayload(@JsonProperty("path") String path, @JsonProperty("query") Map<String, String> query, @JsonProperty("headers") Map<String, String> headers) {}
    record LambdaResponsePayload(@JsonProperty("isBase64Encoded") boolean isBase64Encoded, @JsonProperty("statusCode") int statusCode, @JsonProperty("headers") Map<String, String> headers, @JsonProperty("body") String body) {}
}
