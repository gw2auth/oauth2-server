package com.gw2auth.oauth2.server.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;

import java.net.URI;

@Configuration
public class S3Configuration {

    @Profile("!local")
    @Bean("oauth2-authorization-s3-client")
    public S3Client oauth2ClientS3Client() {
        return S3Client.builder()
                .region(Region.EU_CENTRAL_1)
                .build();
    }

    @Profile("!local")
    @Bean("oauth2-add-federation-s3-client")
    public S3Client oauth2AddFederationS3Client() {
        return S3Client.builder()
                .region(Region.EU_CENTRAL_1)
                .build();
    }

    @Profile("local")
    @Bean("oauth2-authorization-s3-client")
    public S3Client localOAuth2ClientS3Client() {
        return S3Client.builder()
                .region(Region.US_EAST_1)
                .endpointOverride(URI.create("http://localhost:4566"))
                .forcePathStyle(true)
                .build();
    }

    @Profile("local")
    @Bean("oauth2-add-federation-s3-client")
    public S3Client localOAauth2AddFederationS3Client() {
        return S3Client.builder()
                .region(Region.US_EAST_1)
                .endpointOverride(URI.create("http://localhost:4566"))
                .forcePathStyle(true)
                .build();
    }
}
