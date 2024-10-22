package com.gw2auth.oauth2.server.configuration;

import com.gw2auth.oauth2.server.service.security.AuthenticationHelper;
import jakarta.servlet.http.HttpServletRequest;
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

        @Override
        public ClientRegistration findByRegistrationId(String registrationId) {
            final HttpServletRequest request = AuthenticationHelper.getCurrentRequest().orElseThrow();
            final UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request)).build();

            return Optional.ofNullable(uriComponents.getHost())
                    .flatMap((host) -> findBase(registrationId + "@" + host))
                    .or(() -> findBase(registrationId))
                    .map((v) -> maybeChangeAuthorizationURL(v, uriComponents))
                    .orElse(null);
        }

        private Optional<ClientRegistration> findBase(String registrationId) {
            return Optional.ofNullable(this.base.findByRegistrationId(registrationId));
        }

        private ClientRegistration maybeChangeAuthorizationURL(ClientRegistration base, UriComponents uriComponents) {
            if (!Objects.equals(uriComponents.getQueryParams().getFirst("add"), "true")) {
                return base;
            }

            return switch (base.getRegistrationId()) {
                case "cognito" -> changeAuthorizationURLCognito(base);
                case "github", "google" -> changeAuthorizationURLGitHubOrGoogle(base);
                default -> base;
            };
        }

        private ClientRegistration changeAuthorizationURLCognito(ClientRegistration base) {
            // https://docs.aws.amazon.com/cognito/latest/developerguide/logout-endpoint.html
            final String authorizationUri = UriComponentsBuilder.fromHttpUrl(base.getProviderDetails().getAuthorizationUri())
                    .replacePath("/logout")
                    .toUriString();

            return ClientRegistration.withClientRegistration(base)
                    .authorizationUri(authorizationUri)
                    .build();
        }

        private ClientRegistration changeAuthorizationURLGitHubOrGoogle(ClientRegistration base) {
            // https://developers.google.com/identity/openid-connect/openid-connect?hl=de#authenticationuriparameters
            // https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#1-request-a-users-github-identity
            final String authorizationUri = UriComponentsBuilder.fromHttpUrl(base.getProviderDetails().getAuthorizationUri())
                    .replaceQueryParam("prompt", "select_account")
                    .toUriString();

            return ClientRegistration.withClientRegistration(base)
                    .authorizationUri(authorizationUri)
                    .build();
        }
    }
}
