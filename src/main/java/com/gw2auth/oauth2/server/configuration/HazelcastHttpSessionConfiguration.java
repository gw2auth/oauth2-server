package com.gw2auth.oauth2.server.configuration;

import com.gw2auth.oauth2.server.configuration.properties.HazelcastConfigProperties;
import com.hazelcast.config.Config;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingClass;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConditionalOnMissingClass("com.gw2auth.oauth2.server.Gw2AuthTestComponentScan")
@EnableConfigurationProperties(HazelcastConfigProperties.class)
public class HazelcastHttpSessionConfiguration {

    @Bean
    public Config config(HazelcastConfigProperties properties) {
        final Config config = new Config();
        config.setClusterName(properties.getClusterName());
        config.setInstanceName(properties.getInstanceName());

        return config;
    }
}
