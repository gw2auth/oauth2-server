package com.gw2auth.oauth2.server.configuration;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

@TestConfiguration
public class OAuth2ClientConfiguration {

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return (registrationId) -> null;
    }
}
