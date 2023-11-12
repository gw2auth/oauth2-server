package com.gw2auth.oauth2.server.configuration;

import com.gw2auth.oauth2.server.service.security.AuthenticationHelper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientPropertiesMapper;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Configuration
@EnableConfigurationProperties(OAuth2ClientProperties.class)
public class OAuth2ClientConfiguration {

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(OAuth2ClientProperties properties) {
        final List<ClientRegistration> registrations = new ArrayList<>(new OAuth2ClientPropertiesMapper(properties).asClientRegistrations().values());
        return new CustomClientRegistrationRepository(new InMemoryClientRegistrationRepository(registrations));
    }

    private record CustomClientRegistrationRepository(ClientRegistrationRepository base) implements ClientRegistrationRepository {
        @Override
            public ClientRegistration findByRegistrationId(String registrationId) {
                final HttpServletRequest request = AuthenticationHelper.getCurrentRequest().orElseThrow();
                final UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request)).build();

                return Optional.ofNullable(uriComponents.getHost())
                        .map((host) -> this.base.findByRegistrationId(registrationId + "@" + host))
                        .orElseGet(() -> this.base.findByRegistrationId(registrationId));
            }
        }
}
