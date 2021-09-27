package com.gw2auth.oauth2.server.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;

@Configuration
public class SelfProxyRestConfiguration {

    @Bean("self-proxy-rest-template")
    public RestTemplate selfProxyRestTemplate(@Value("${server.port}") int port) {
        return new RestTemplateBuilder()
                .rootUri("http://127.0.0.1:" + port)
                .setConnectTimeout(Duration.ofMillis(100L))
                .setReadTimeout(Duration.ofSeconds(1L))
                .errorHandler(new ResponseErrorHandler() {
                    // interpret nothing as an error (handle it on the caller side)
                    @Override
                    public boolean hasError(ClientHttpResponse response) {
                        return false;
                    }

                    @Override
                    public void handleError(ClientHttpResponse response) {

                    }
                })
                .build();
    }
}
