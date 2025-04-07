package com.gw2auth.oauth2.server.configuration;

import com.gw2auth.oauth2.server.service.security.AuthenticationHelper;
import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;
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
        public @Nullable ClientRegistration findByRegistrationId(String registrationId) {
            final HttpServletRequest request = AuthenticationHelper.getCurrentRequest().orElseThrow();
            final UriComponents uriComponents = UriComponentsBuilder.fromUriString(UrlUtils.buildFullRequestUrl(request)).build();

            return Optional.ofNullable(uriComponents.getHost())
                    .flatMap((host) -> findBase(registrationId + "@" + host))
                    .or(() -> findBase(registrationId))
                    .map(CustomClientRegistrationRepository::changeAuthorizationURL)
                    .orElse(null);
        }

        private Optional<ClientRegistration> findBase(String registrationId) {
            return Optional.ofNullable(this.base.findByRegistrationId(registrationId));
        }

        private static ClientRegistration changeAuthorizationURL(ClientRegistration base) {
            // Google and GitHub provider details are populated by org.springframework.security.config.oauth2.client.CommonOAuth2Provider

            final String issuerUri = base.getProviderDetails().getIssuerUri();
            if (issuerUri != null && !issuerUri.isEmpty()) {
                final UriComponents uriComponents = UriComponentsBuilder.fromUriString(issuerUri).build();
                final String host = uriComponents.getHost();

                if (host != null) {
                    if (host.startsWith("cognito-idp") && host.endsWith("amazonaws.com")) {
                        return changeAuthorizationURLCognito(base);
                    } else if (Objects.equals(host, "accounts.google.com")) {
                        return changeAuthorizationURLGitHubOrGoogle(base);
                    } else if (Objects.equals(host, "gw2auth.com")) {
                        return changeAuthorizationURLGw2auth(base);
                    }
                }
            }

            // GitHub provider details dont have a issuer uri, use authorization uri for detection instead
            final String authorizationUri = base.getProviderDetails().getAuthorizationUri();
            if (authorizationUri != null && !authorizationUri.isEmpty()) {
                final UriComponents uriComponents = UriComponentsBuilder.fromUriString(authorizationUri).build();
                final String host = uriComponents.getHost();

                if (Objects.equals(host, "github.com")) {
                    return changeAuthorizationURLGitHubOrGoogle(base);
                }
            }

            return base;
        }

        private static ClientRegistration changeAuthorizationURLCognito(ClientRegistration base) {
            // https://docs.aws.amazon.com/cognito/latest/developerguide/logout-endpoint.html
            final String authorizationUri = UriComponentsBuilder.fromUriString(base.getProviderDetails().getAuthorizationUri())
                    .replacePath("/logout")
                    .toUriString();

            return ClientRegistration.withClientRegistration(base)
                    .authorizationUri(authorizationUri)
                    .build();
        }

        private static ClientRegistration changeAuthorizationURLGitHubOrGoogle(ClientRegistration base) {
            // https://developers.google.com/identity/openid-connect/openid-connect?hl=de#authenticationuriparameters
            // https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps#1-request-a-users-github-identity
            final String authorizationUri = UriComponentsBuilder.fromUriString(base.getProviderDetails().getAuthorizationUri())
                    .replaceQueryParam("prompt", "select_account")
                    .toUriString();

            return ClientRegistration.withClientRegistration(base)
                    .authorizationUri(authorizationUri)
                    .build();
        }

        private static ClientRegistration changeAuthorizationURLGw2auth(ClientRegistration base) {
            // https://github.com/gw2auth/oauth2-server/wiki/GW2Auth-Developer-Guide#redirect-the-user-to-the-authorization_endpoint
            final String authorizationUri = UriComponentsBuilder.fromUriString(base.getProviderDetails().getAuthorizationUri())
                    .replaceQueryParam("prompt", "consent")
                    .toUriString();

            return ClientRegistration.withClientRegistration(base)
                    .authorizationUri(authorizationUri)
                    .build();
        }
    }
}
