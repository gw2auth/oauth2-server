package com.gw2auth.oauth2.server.configuration;

import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class S3Configuration {

    @Bean("oauth2-authorization-s3-client")
    public AmazonS3 oauth2ClientS3Client() {
        return AmazonS3Client.builder()
                .withRegion(Regions.EU_CENTRAL_1)
                .build();
    }

    @Bean("oauth2-add-federation-s3-client")
    public AmazonS3 oauth2AddFederationS3Client() {
        return AmazonS3Client.builder()
                .withRegion(Regions.EU_CENTRAL_1)
                .build();
    }
}
