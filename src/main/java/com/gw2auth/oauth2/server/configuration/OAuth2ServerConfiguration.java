package com.gw2auth.oauth2.server.configuration;

import com.gw2auth.oauth2.server.adapt.CustomOAuth2AuthorizationCodeRequestAuthenticationProvider;
import com.gw2auth.oauth2.server.util.JWKHelper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer;
import org.springframework.security.config.annotation.web.configurers.SecurityContextConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.UUID;

@Configuration
public class OAuth2ServerConfiguration {

    public static final String OAUTH2_CONSENT_PAGE = "/oauth2/consent";

    @Bean("oidc-server-request-matcher")
    public RequestMatcher oidcServerRequestMatcher() {
        return new OrRequestMatcher(
                new AntPathRequestMatcher("/.well-known/openid-configuration"),
                new AntPathRequestMatcher("/connect/register"),
                new AntPathRequestMatcher("/userinfo")
        );
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain oidcServerHttpSecurityFilterChain(HttpSecurity http, @Qualifier("oidc-server-request-matcher") RequestMatcher requestMatcher) throws Exception {
        http
                .requestMatcher(requestMatcher)
                .addFilterBefore(new OncePerRequestFilter() {
                    @Override
                    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
                        response.setStatus(HttpStatus.NOT_FOUND.value());
                    }
                }, SecurityContextHolderFilter.class);

        return http.build();
    }

    @Bean
    public OAuth2AuthorizationServerConfigurer<HttpSecurity> oAuth2AuthorizationServerConfigurer(HttpSecurity http) {
        final OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer<>();
        authorizationServerConfigurer.authorizationEndpoint((authorizationEndpoint) -> {
            authorizationEndpoint
                    .authenticationProvider(CustomOAuth2AuthorizationCodeRequestAuthenticationProvider.create(http))
                    .consentPage(OAUTH2_CONSENT_PAGE);
        });

        return authorizationServerConfigurer;
    }

    @Bean("oauth2-server-request-matcher")
    public RequestMatcher oauth2ServerRequestMatcher(OAuth2AuthorizationServerConfigurer<HttpSecurity> configurer) {
        return configurer.getEndpointsMatcher();
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 1)
    public SecurityFilterChain oauth2ServerHttpSecurityFilterChain(HttpSecurity http,
                                                                   @Qualifier("oauth2-server-request-matcher") RequestMatcher requestMatcher,
                                                                   OAuth2AuthorizationServerConfigurer<HttpSecurity> configurer,
                                                                   Customizer<SecurityContextConfigurer<HttpSecurity>> securityContextCustomizer,
                                                                   Customizer<RequestCacheConfigurer<HttpSecurity>> requestCacheCustomizer,
                                                                   Customizer<OAuth2LoginConfigurer<HttpSecurity>> oauth2LoginCustomizer,
                                                                   Customizer<OAuth2ResourceServerConfigurer<HttpSecurity>> oauth2ResourceServerCustomizer) throws Exception {

        // This configuration is only for requests matched by the RequestMatcher
        // (that is, only OAuth2 AUTHORIZATION requests -> requests where this application acts as a OAuth2 server, not a client)
        http
                .requestMatcher(requestMatcher)
                .authorizeRequests((auth) -> auth.anyRequest().authenticated())
                .csrf((csrf) -> csrf.ignoringRequestMatchers(requestMatcher))
                .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .securityContext(securityContextCustomizer)
                .requestCache(requestCacheCustomizer)
                .oauth2Login(oauth2LoginCustomizer)
                .oauth2ResourceServer(oauth2ResourceServerCustomizer)
                .apply(configurer);

        return http.build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(@Value("${com.gw2auth.oauth2.keypair.id}") String keyPairId,
                                                @Value("${com.gw2auth.oauth2.keypair.path}") String keyPairPath) throws IOException, GeneralSecurityException, JOSEException {

        if (keyPairId.equals("generate")) {
            keyPairId = UUID.randomUUID().toString();
        }

        final KeyPair keyPair;

        if (keyPairPath.equals("generate")) {
            keyPair = JWKHelper.generateRsaKeyPair();
        } else {
            keyPair = JWKHelper.loadRsaKeyPair(keyPairPath, keyPairPath + ".pub");
        }

        return JWKHelper.jwkSourceForKeyPair(keyPair, keyPairId);
    }

    @Bean
    public ProviderSettings providerSettings(@Value("${com.gw2auth.url}") String selfURL) {
        return ProviderSettings.builder().issuer(selfURL).build();
    }
}
