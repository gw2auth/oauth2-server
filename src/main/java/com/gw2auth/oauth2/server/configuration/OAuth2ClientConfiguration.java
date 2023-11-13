package com.gw2auth.oauth2.server.configuration;

import com.gw2auth.oauth2.server.service.security.AuthenticationHelper;
import com.gw2auth.oauth2.server.util.Pair;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.security.oauth2.client.ClientsConfiguredCondition;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientPropertiesMapper;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Configuration
@EnableConfigurationProperties(OAuth2ClientProperties.class)
@Conditional(ClientsConfiguredCondition.class)
public class OAuth2ClientConfiguration {

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(OAuth2ClientProperties properties) {
        final List<ClientRegistration> registrations = new ArrayList<>(new OAuth2ClientPropertiesMapper(properties).asClientRegistrations().values());
        return new CustomClientRegistrationRepository(new InMemoryClientRegistrationRepository(registrations));
    }

    private record CustomClientRegistrationRepository(ClientRegistrationRepository base) implements ClientRegistrationRepository {

        private static final Logger LOG = LoggerFactory.getLogger(CustomClientRegistrationRepository.class);

        @Override
        public ClientRegistration findByRegistrationId(String registrationId) {
            final HttpServletRequest request = AuthenticationHelper.getCurrentRequest().orElseThrow();
            final UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request)).build();

            LOG.info("resolved UriComponents: {} (host={})", uriComponents, uriComponents.getHost());
            try {
                logRequest(request);
            } catch (Exception e) {
                LOG.warn("failed to log request", e);
            }

            return Optional.ofNullable(uriComponents.getHost())
                    .flatMap((host) -> findBase(registrationId + "@" + host))
                    .or(() -> findBase(registrationId))
                    .orElse(null);
        }

        private Optional<ClientRegistration> findBase(String registrationId) {
            return Optional.ofNullable(this.base.findByRegistrationId(registrationId));
        }

        private static void logRequest(HttpServletRequest request) {
            final Map<String, List<String>> headers = Stream.of("X-Forwarded-For", "X-Forwarded-Host", "Forwarded", "Host")
                    .flatMap((v) -> {
                        final Enumeration<String> enumeration = request.getHeaders(v);
                        if (enumeration == null) {
                            return Stream.empty();
                        }

                        final List<String> values = new ArrayList<>();
                        final Iterator<String> it = enumeration.asIterator();
                        while (it.hasNext()) {
                            values.add(it.next());
                        }

                        return Stream.of(new Pair<>(v, values));
                    })
                    .collect(Collectors.toMap(Pair::v1, Pair::v2));

            final String serverName = request.getServerName();

            LOG.info("ClientRegistrationRepository; request with serverName={} and headers={}", serverName, headers);
        }
    }
}
