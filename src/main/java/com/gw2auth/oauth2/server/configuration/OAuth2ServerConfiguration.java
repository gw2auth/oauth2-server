package com.gw2auth.oauth2.server.configuration;

import com.gw2auth.oauth2.server.adapt.CustomOAuth2ServerAuthenticationProviders;
import com.gw2auth.oauth2.server.service.application.AuthorizationCodeParamAccessor;
import com.gw2auth.oauth2.server.util.JWKHelper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer;
import org.springframework.security.config.annotation.web.configurers.SecurityContextConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;

@Configuration
public class OAuth2ServerConfiguration {

    public static final String OAUTH2_CONSENT_PAGE = "/oauth2-consent";

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
                .securityMatcher(requestMatcher)
                .addFilterBefore(new OncePerRequestFilter() {
                    @Override
                    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
                        response.setStatus(HttpStatus.NOT_FOUND.value());
                    }
                }, SecurityContextHolderFilter.class);

        return http.build();
    }

    @Bean
    public OAuth2AuthorizationServerConfigurer oAuth2AuthorizationServerConfigurer(HttpSecurity http) {
        final OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        authorizationServerConfigurer.authorizationEndpoint((authorizationEndpoint) -> {
            authorizationEndpoint
                    .authenticationProviders((authenticationProviders) -> {
                        authenticationProviders.removeIf((v) -> OAuth2AuthorizationCodeRequestAuthenticationProvider.class.isAssignableFrom(v.getClass()));
                        authenticationProviders.removeIf((v) -> OAuth2AuthorizationConsentAuthenticationProvider.class.isAssignableFrom(v.getClass()));

                        authenticationProviders.add(CustomOAuth2ServerAuthenticationProviders.createCodeRequestAuthenticationProvider(http));
                        authenticationProviders.add(CustomOAuth2ServerAuthenticationProviders.createConsentAuthenticationProvider(http));
                    })
                    .consentPage(OAUTH2_CONSENT_PAGE);
        });

        return authorizationServerConfigurer;
    }

    @Bean("oauth2-server-request-matcher")
    public RequestMatcher oauth2ServerRequestMatcher(OAuth2AuthorizationServerConfigurer configurer) {
        return configurer.getEndpointsMatcher();
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 1)
    public SecurityFilterChain oauth2ServerHttpSecurityFilterChain(HttpSecurity http,
                                                                   @Qualifier("oauth2-server-request-matcher") RequestMatcher requestMatcher,
                                                                   OAuth2AuthorizationServerConfigurer configurer,
                                                                   Customizer<SecurityContextConfigurer<HttpSecurity>> securityContextCustomizer,
                                                                   Customizer<RequestCacheConfigurer<HttpSecurity>> requestCacheCustomizer,
                                                                   Customizer<OAuth2LoginConfigurer<HttpSecurity>> oauth2LoginCustomizer) throws Exception {

        // This configuration is only for requests matched by the RequestMatcher
        // (that is, only OAuth2 AUTHORIZATION requests -> requests where this application acts as a OAuth2 server, not a client)
        http
                .securityMatcher(requestMatcher)
                .authorizeHttpRequests((auth) -> auth.anyRequest().authenticated())
                .csrf((csrf) -> csrf.ignoringRequestMatchers(requestMatcher))
                .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .securityContext(securityContextCustomizer)
                .requestCache(requestCacheCustomizer)
                .oauth2Login(oauth2LoginCustomizer)
                .apply(configurer);

        return http.build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(@Value("${com.gw2auth.oauth2.keypair.id}") String keyPairId,
                                                @Value("${com.gw2auth.oauth2.keypair.path}") String keyPairPath,
                                                Environment environment) throws IOException, GeneralSecurityException, JOSEException {

        final KeyPair keyPair;
        if (keyPairPath.equals("generate")) {
            if (!environment.acceptsProfiles(Profiles.of("test"))) {
                throw new IllegalStateException("key generation only enabled for tests");
            }

            keyPair = JWKHelper.generateRsaKeyPair();
        } else {
            keyPair = JWKHelper.loadRsaKeyPair(keyPairPath, keyPairPath + ".pub");
        }

        return JWKHelper.jwkSourceForKeyPair(keyPair, keyPairId);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings(@Value("${com.gw2auth.url}") String selfURL) {
        return AuthorizationServerSettings.builder().issuer(selfURL).build();
    }

    @Bean
    public AuthorizationCodeParamAccessor authorizationCodeParamAccessor() {
        return AuthorizationCodeParamAccessor.DEFAULT;
    }
}
