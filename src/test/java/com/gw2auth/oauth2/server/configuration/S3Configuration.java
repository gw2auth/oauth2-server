package com.gw2auth.oauth2.server.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;

@Configuration
public class S3Configuration {

    @Bean
    public LocalStackContainer localStackContainer() {
        final LocalStackContainer localStackContainer = new LocalStackContainer(DockerImageName.parse("localstack/localstack:4.2")).withServices(LocalStackContainer.Service.S3);
        localStackContainer.start();

        return localStackContainer;
    }

    @Bean("oauth2-authorization-s3-client")
    public S3Client oauth2ClientS3Client(LocalStackContainer localStackContainer, @Value("${com.gw2auth.oauth2.client.s3.bucket}") String bucket) {
        final S3Client s3 = s3Client(localStackContainer);
        s3.createBucket(CreateBucketRequest.builder().bucket(bucket).build());

        return s3;
    }

    @Bean("oauth2-add-federation-s3-client")
    public S3Client addFederationS3Client(LocalStackContainer localStackContainer, @Value("${com.gw2auth.oauth2.addfederation.s3.bucket}") String bucket) {
        final S3Client s3 = s3Client(localStackContainer);
        s3.createBucket(CreateBucketRequest.builder().bucket(bucket).build());

        return s3;
    }

    private S3Client s3Client(LocalStackContainer localStackContainer) {
        return S3Client.builder()
                .region(Region.of(localStackContainer.getRegion()))
                .endpointOverride(localStackContainer.getEndpointOverride(LocalStackContainer.Service.S3))
                .credentialsProvider(
                        StaticCredentialsProvider.create(
                                AwsBasicCredentials.create(
                                        localStackContainer.getAccessKey(),
                                        localStackContainer.getSecretKey()
                                )
                        )
                )
                .build();
    }
}
