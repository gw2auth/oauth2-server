package com.gw2auth.oauth2.server.configuration;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

@TestConfiguration
public class SelfProxyRestConfiguration {

    @Primary
    @Bean("self-proxy-rest-template")
    public RestTemplate selfProxyRestTemplate() {
        final RestTemplate restTemplate = new RestTemplate();
        final MockRestServiceServer server = MockRestServiceServer.bindTo(restTemplate).build();

        return restTemplate;
    }
}
