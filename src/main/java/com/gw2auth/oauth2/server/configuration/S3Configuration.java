package com.gw2auth.oauth2.server.configuration;

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration
public class S3Configuration {

    @Profile("!local")
    @Bean("oauth2-authorization-s3-client")
    public AmazonS3 oauth2ClientS3Client() {
        return AmazonS3Client.builder()
                .withRegion(Regions.EU_CENTRAL_1)
                .build();
    }

    @Profile("!local")
    @Bean("oauth2-add-federation-s3-client")
    public AmazonS3 oauth2AddFederationS3Client() {
        return AmazonS3Client.builder()
                .withRegion(Regions.EU_CENTRAL_1)
                .build();
    }

    @Profile("local")
    @Bean("oauth2-authorization-s3-client")
    public AmazonS3 localOAuth2ClientS3Client() {
        return AmazonS3Client.builder()
                .withEndpointConfiguration(new AwsClientBuilder.EndpointConfiguration("http://localhost:4566", "us-east-1"))
                .enablePathStyleAccess()
                .build();
    }

    @Profile("local")
    @Bean("oauth2-add-federation-s3-client")
    public AmazonS3 localOAauth2AddFederationS3Client() {
        return AmazonS3Client.builder()
                .withEndpointConfiguration(new AwsClientBuilder.EndpointConfiguration("http://localhost:4566", "us-east-1"))
                .enablePathStyleAccess()
                .build();
    }
}
