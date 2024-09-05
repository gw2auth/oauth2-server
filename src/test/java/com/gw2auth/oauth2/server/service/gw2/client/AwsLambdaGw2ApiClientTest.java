package com.gw2auth.oauth2.server.service.gw2.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.InvokeRequest;
import software.amazon.awssdk.services.lambda.model.InvokeResponse;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AwsLambdaGw2ApiClientTest {

    @Test
    public void getHappycaseBase64() throws Exception{
        final ObjectMapper mapper = new ObjectMapper();
        final ArgumentCaptor<InvokeRequest> lambdaRequestCaptor = ArgumentCaptor.forClass(InvokeRequest.class);
        final LambdaClient lambdaClient = mock(LambdaClient.class);
        when(lambdaClient.invoke(lambdaRequestCaptor.capture())).thenReturn(
                InvokeResponse.builder()
                        .payload(SdkBytes.fromString(
                                """
                                        {
                                            "isBase64Encoded": true,
                                            "statusCode": 200,
                                            "headers": {
                                                "some": "response_header"
                                            },
                                            "body": "$BODY"
                                        }
                                        """.replace("$BODY", Base64.getEncoder().encodeToString("{}".getBytes(StandardCharsets.UTF_8))),
                                StandardCharsets.UTF_8
                        ))
                        .build()
        );

        final AwsLambdaGw2ApiClient gw2ApiClient = new AwsLambdaGw2ApiClient(lambdaClient, "functionName", mapper);
        final MultiValueMap<String, String> requestQuery = new LinkedMultiValueMap<>();
        requestQuery.add("some", "query");

        final MultiValueMap<String, String> requestHeaders = new HttpHeaders();
        requestHeaders.add("some", "header");

        final ResponseEntity<Resource> response = gw2ApiClient.get("/some/path", requestQuery, requestHeaders);

        // lambda request
        final InvokeRequest lambdaRequest = lambdaRequestCaptor.getValue();
        assertEquals("functionName", lambdaRequest.functionName());
        assertEquals(
                mapper.readTree("""
                        {
                            "path": "/some/path",
                            "query": {
                                "some": "query"
                            },
                            "headers": {
                                "some": "header"
                            }
                        }
                        """),
                mapper.readTree(lambdaRequest.payload().asUtf8String())
        );

        // response
        final MultiValueMap<String, String> responseHeaders = new HttpHeaders();
        responseHeaders.add("some", "response_header");

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(responseHeaders, response.getHeaders());
        assertEquals(
                mapper.readTree("{}"),
                mapper.readTree(response.getBody().getContentAsString(StandardCharsets.UTF_8))
        );
    }

    @Test
    public void getHappycase() throws Exception{
        final ObjectMapper mapper = new ObjectMapper();
        final ArgumentCaptor<InvokeRequest> lambdaRequestCaptor = ArgumentCaptor.forClass(InvokeRequest.class);
        final LambdaClient lambdaClient = mock(LambdaClient.class);
        when(lambdaClient.invoke(lambdaRequestCaptor.capture())).thenReturn(
                InvokeResponse.builder()
                        .payload(SdkBytes.fromString(
                                """
                                        {
                                            "isBase64Encoded": false,
                                            "statusCode": 200,
                                            "headers": {
                                                "some": "response_header"
                                            },
                                            "body": "{}"
                                        }
                                        """,
                                StandardCharsets.UTF_8
                        ))
                        .build()
        );

        final AwsLambdaGw2ApiClient gw2ApiClient = new AwsLambdaGw2ApiClient(lambdaClient, "functionName", mapper);
        final MultiValueMap<String, String> requestQuery = new LinkedMultiValueMap<>();
        requestQuery.add("some", "query");

        final MultiValueMap<String, String> requestHeaders = new HttpHeaders();
        requestHeaders.add("some", "header");

        final ResponseEntity<Resource> response = gw2ApiClient.get("/some/path", requestQuery, requestHeaders);

        // lambda request
        final InvokeRequest lambdaRequest = lambdaRequestCaptor.getValue();
        assertEquals("functionName", lambdaRequest.functionName());
        assertEquals(
                mapper.readTree("""
                        {
                            "path": "/some/path",
                            "query": {
                                "some": "query"
                            },
                            "headers": {
                                "some": "header"
                            }
                        }
                        """),
                mapper.readTree(lambdaRequest.payload().asUtf8String())
        );

        // response
        final MultiValueMap<String, String> responseHeaders = new HttpHeaders();
        responseHeaders.add("some", "response_header");

        assertEquals(HttpStatus.OK, response.getStatusCode());
        assertEquals(responseHeaders, response.getHeaders());
        assertEquals(
                mapper.readTree("{}"),
                mapper.readTree(response.getBody().getContentAsString(StandardCharsets.UTF_8))
        );
    }
}