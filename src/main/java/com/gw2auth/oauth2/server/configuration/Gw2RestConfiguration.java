package com.gw2auth.oauth2.server.configuration;

import org.springframework.boot.actuate.metrics.web.client.MetricsRestTemplateCustomizer;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;

@Configuration
public class Gw2RestConfiguration {

    @Bean("gw2-rest-template")
    public RestTemplate gw2RestTemplate(MetricsRestTemplateCustomizer metricsRestTemplateCustomizer) {
        return new RestTemplateBuilder()
                .rootUri("https://api.guildwars2.com")
                .setConnectTimeout(Duration.ofSeconds(3L))
                .setReadTimeout(Duration.ofSeconds(5L))
                .customizers(metricsRestTemplateCustomizer)
                .build();
    }
}
