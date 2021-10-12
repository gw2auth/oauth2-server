package com.gw2auth.oauth2.server.configuration;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

@Configuration
public class Gw2RestConfiguration {

    @Primary
    @Bean("gw2-rest-template")
    public RestTemplate gw2RestTemplate() {
        return new RestTemplate();
    }

    @Bean("gw2-rest-server")
    public MockRestServiceServer gw2RestServer(@Qualifier("gw2-rest-template") RestTemplate gw2RestTemplate) {
        return MockRestServiceServer.bindTo(gw2RestTemplate).build();
    }
}
