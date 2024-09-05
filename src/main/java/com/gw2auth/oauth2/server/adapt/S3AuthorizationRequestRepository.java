package com.gw2auth.oauth2.server.adapt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.client.jackson2.OAuth2ClientJackson2Module;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

public class S3AuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    private static final Logger LOG = LoggerFactory.getLogger(S3AuthorizationRequestRepository.class);
    private final S3Client s3;
    private final String bucket;
    private final String prefix;
    private final ObjectMapper mapper;

    public S3AuthorizationRequestRepository(S3Client s3, String bucket, String prefix) {
        this.s3 = s3;
        this.bucket = bucket;
        this.prefix = prefix;

        // make sure to add support for OAuth2AuthorizationRequest
        final ObjectMapper mapper = new ObjectMapper();
        mapper.registerModules(SecurityJackson2Modules.getModules(S3AuthorizationRequestRepository.class.getClassLoader()));
        mapper.registerModule(new OAuth2ClientJackson2Module());
        mapper.registerModule(new Java9CollectionJackson2Module());
        mapper.registerModule(new LinkedHashSetJackson2Module());

        this.mapper = mapper;
    }

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        final String state = getState(request);
        if (state == null) {
            return null;
        }

        return loadAuthorizationRequest(state).orElse(null);
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request, HttpServletResponse response) {
        if (authorizationRequest == null) {
            final String state = getState(request);
            if (state != null) {
                deleteAuthorizationRequest(state);
            }
        } else {
            saveAuthorizationRequest(authorizationRequest.getState(), authorizationRequest);
        }
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
        final String state = getState(request);
        if (state == null) {
            return null;
        }

        final OAuth2AuthorizationRequest oldRequest = loadAuthorizationRequest(state).orElse(null);
        deleteAuthorizationRequest(state);

        return oldRequest;
    }

    private String getState(HttpServletRequest request) {
        return request.getParameter(OAuth2ParameterNames.STATE);
    }

    private Optional<OAuth2AuthorizationRequest> loadAuthorizationRequest(String state) {
        OAuth2AuthorizationRequest request = null;

        final GetObjectRequest s3Request = GetObjectRequest.builder()
                .bucket(this.bucket)
                .key(buildS3ObjectKey(state))
                .build();

        try (ResponseInputStream<GetObjectResponse> response = this.s3.getObject(s3Request)) {
            request = this.mapper.readValue(response, OAuth2AuthorizationRequest.class);
        } catch (NoSuchKeyException e) {
            LOG.info("requested key does not exist", e);
        } catch (S3Exception e) {
            LOG.warn("got unexpected S3Exception when trying to access OAuth2AuthorizationRequest", e);
        } catch (IOException e) {
            LOG.warn("got unexpected IOException when trying to access OAuth2AuthorizationRequest", e);
        }

        return Optional.ofNullable(request);
    }

    private void saveAuthorizationRequest(String state, OAuth2AuthorizationRequest request) {
        final String json;
        try {
            json = this.mapper.writeValueAsString(request);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }

        final PutObjectRequest s3Request = PutObjectRequest.builder()
                .bucket(this.bucket)
                .key(buildS3ObjectKey(state))
                .build();

        this.s3.putObject(s3Request, RequestBody.fromString(json, StandardCharsets.UTF_8));
    }

    private void deleteAuthorizationRequest(String state) {
        final DeleteObjectRequest s3Request = DeleteObjectRequest.builder()
                .bucket(this.bucket)
                .key(buildS3ObjectKey(state))
                .build();

        try {
            this.s3.deleteObject(s3Request);
        } catch (S3Exception e) {
            // dont fail if key didnt exist
            if (e.statusCode() != HttpStatus.NOT_FOUND.value()) {
                throw e;
            }
        }
    }

    private String buildS3ObjectKey(String state) {
        return this.prefix + state;
    }
}
