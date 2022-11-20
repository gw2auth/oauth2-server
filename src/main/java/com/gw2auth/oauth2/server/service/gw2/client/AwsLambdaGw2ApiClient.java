package com.gw2auth.oauth2.server.service.gw2.client;

import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.model.*;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.util.ByteBufferBackedInputStream;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;

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
        final InvokeResult result = this.awsLambda.invoke(invokeRequest);

        if (result.getFunctionError() != null) {
            throw new AWSLambdaException(result.getFunctionError());
        }

        final int statusCode;
        final HttpHeaders responseHeaders;
        final byte[] body;

        try (InputStream in = new ByteBufferBackedInputStream(result.getPayload())) {
            final LambdaResponsePayload response = this.mapper.readValue(in, LambdaResponsePayload.class);

            statusCode = response.statusCode();
            responseHeaders = new HttpHeaders();
            response.headers().forEach(responseHeaders::add);

            if (response.isBase64Encoded()) {
                body = Base64.getDecoder().decode(response.body());
            } else {
                body = response.body().getBytes(StandardCharsets.UTF_8);
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
