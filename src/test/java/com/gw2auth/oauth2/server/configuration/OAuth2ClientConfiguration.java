package com.gw2auth.oauth2.server.configuration;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@TestConfiguration
public class OAuth2ClientConfiguration {

    @Bean
    public TestClientRegistrationRepository clientRegistrationRepository() {
        return new TestClientRegistrationRepository();
    }

    @Bean("testOAuth2LoginCustomizer")
    @Primary
    public Customizer<OAuth2LoginConfigurer<HttpSecurity>> oauth2LoginCustomizer() {
        return (oauth2) -> oauth2.tokenEndpoint().accessTokenResponseClient(accessTokenResponseClient());
    }

    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
        return (request) -> {
            final String jwt = new PlainJWT(
                    new JWTClaimsSet.Builder()
                            .subject(request.getAuthorizationExchange().getAuthorizationResponse().getCode())
                            .build()
            ).serialize();

            return OAuth2AccessTokenResponse.withToken(jwt)
                    .expiresIn(60L * 24L * 365L)
                    .scopes(Set.of("dummy-scope"))
                    .tokenType(OAuth2AccessToken.TokenType.BEARER)
                    .build();
        };
    }

    public static class TestClientRegistrationRepository implements ClientRegistrationRepository {

        private final Map<String, ClientRegistration> clientRegistrations;

        public TestClientRegistrationRepository() {
            this.clientRegistrations = new ConcurrentHashMap<>();
        }

        @Override
        public ClientRegistration findByRegistrationId(String registrationId) {
            return this.clientRegistrations.get(registrationId);
        }

        public void prepareRegistrationId(String registrationId) {
            final ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(registrationId)
                    .clientName("Test")
                    .clientId("dummy-id-" + registrationId)
                    .clientSecret("dummy-secret")
                    .scope("dummy-scope")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationUri("https://dummy.gw2auth.com/oauth2/authorize")
                    .tokenUri("https://dummy.gw2auth.com/oauth2/token")
                    .userInfoUri("https://dummy.gw2auth.com/oauth2/userinfo")
                    .redirectUri("http://localhost/login/oauth2/code/" + registrationId)
                    .userNameAttributeName("sub")
                    .build();

            this.clientRegistrations.put(registrationId, clientRegistration);
        }
    }
}
