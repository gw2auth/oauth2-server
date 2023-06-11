package com.gw2auth.oauth2.server.configuration;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.utility.DockerImageName;

@Configuration
public class S3Configuration {

    @Bean
    public LocalStackContainer localStackContainer() {
        final LocalStackContainer localStackContainer = new LocalStackContainer(DockerImageName.parse("localstack/localstack:2.2")).withServices(LocalStackContainer.Service.S3);
        localStackContainer.start();

        return localStackContainer;
    }

    @Bean("oauth2-authorization-s3-client")
    public AmazonS3 oauth2ClientS3Client(LocalStackContainer localStackContainer, @Value("${com.gw2auth.oauth2.client.s3.bucket}") String bucket) {
        final AmazonS3 s3 = s3Client(localStackContainer);
        s3.createBucket(bucket);

        return s3;
    }

    @Bean("oauth2-add-federation-s3-client")
    public AmazonS3 addFederationS3Client(LocalStackContainer localStackContainer, @Value("${com.gw2auth.oauth2.addfederation.s3.bucket}") String bucket) {
        final AmazonS3 s3 = s3Client(localStackContainer);
        s3.createBucket(bucket);

        return s3;
    }

    private AmazonS3 s3Client(LocalStackContainer localStackContainer) {
        return AmazonS3ClientBuilder
                .standard()
                .withEndpointConfiguration(
                        new AwsClientBuilder.EndpointConfiguration(
                                localStackContainer.getEndpointOverride(LocalStackContainer.Service.S3).toString(),
                                localStackContainer.getRegion()
                        )
                )
                .withCredentials(
                        new AWSStaticCredentialsProvider(
                                new BasicAWSCredentials(localStackContainer.getAccessKey(), localStackContainer.getSecretKey())
                        )
                )
                .build();
    }
}
