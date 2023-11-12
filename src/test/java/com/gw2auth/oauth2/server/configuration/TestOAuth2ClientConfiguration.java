package com.gw2auth.oauth2.server.configuration;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;

import java.util.Set;

@TestConfiguration
public class TestOAuth2ClientConfiguration {

    @Bean("testClientRegistrationRepository")
    @Primary
    public TestClientRegistrationRepository clientRegistrationRepository() {
        return new TestClientRegistrationRepository();
    }

    @Bean("testOAuth2LoginCustomizer")
    @Primary
    public Customizer<OAuth2LoginConfigurer<HttpSecurity>> oauth2LoginCustomizer(@Qualifier("oauth2LoginCustomizer") Customizer<OAuth2LoginConfigurer<HttpSecurity>> oauth2LoginCustomizer) {
        return oauth2 -> {
            oauth2LoginCustomizer.customize(oauth2);
            oauth2.tokenEndpoint((tk) -> tk.accessTokenResponseClient(accessTokenResponseClient()));
        };
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

}
