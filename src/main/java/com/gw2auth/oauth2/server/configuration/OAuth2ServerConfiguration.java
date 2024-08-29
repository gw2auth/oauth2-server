package com.gw2auth.oauth2.server.configuration;

import com.gw2auth.oauth2.server.adapt.CustomOAuth2ServerAuthenticationProviders;
import com.gw2auth.oauth2.server.service.application.AuthorizationCodeParamAccessor;
import com.gw2auth.oauth2.server.util.ComposedMDCCloseable;
import com.gw2auth.oauth2.server.util.JWKHelper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
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
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.*;
import java.util.function.Function;

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
                    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
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
                .with(configurer, ignored -> {})
                .addFilterBefore(new OAuth2ServerLoggingFilter(), SecurityContextHolderFilter.class);

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

    private static class OAuth2ServerLoggingFilter extends OncePerRequestFilter {

        private static final Logger LOG = LoggerFactory.getLogger(OAuth2ServerLoggingFilter.class);

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
            Map<String, String> requestAttributes;
            try {
                requestAttributes = buildRequestAttributes(request);
            } catch (Exception e) {
                // better be safe than sorry
                LOG.warn("failed to build request attributes", e);
                requestAttributes = Map.of();
            }

            Exception exc = null;
            try {
                filterChain.doFilter(request, response);
            } catch (Exception e) {
                exc = e;
            }

            Map<String, String> responseAttributes;
            try {
                responseAttributes = buildResponseAttributes(response);
            } catch (Exception e) {
                LOG.warn("failed to build response attributes", e);
                responseAttributes = Map.of();
            }

            try (ComposedMDCCloseable _unused = ComposedMDCCloseable.create(requestAttributes, Object::toString)) {
                try (ComposedMDCCloseable __unused = ComposedMDCCloseable.create(responseAttributes, Object::toString)) {
                    if (exc == null) {
                        LOG.info("oauth2 request handled successfully");
                    } else {
                        LOG.info("oauth2 request failed", exc);
                    }
                }
            }

            if (exc != null) {
                switch (exc) {
                    case ServletException e:
                        throw e;

                    case IOException e:
                        throw e;

                    case RuntimeException e:
                        throw e;

                    default:
                        throw new RuntimeException("Unexpected error occurred while logging request", exc);
                }
            }
        }

        private static Map<String, String> buildRequestAttributes(HttpServletRequest request) {
            final UriComponents uriComponents = UriComponentsBuilder.fromUriString(request.getRequestURI())
                    .query(request.getQueryString())
                    .build();

            final Map<String, String> attributes = new HashMap<>();
            attributes.put("request.method", request.getMethod());
            attributes.put("request.url", uriComponents.getPath());
            uriComponents.getQueryParams().forEach((key, value) -> {
                if (!key.equalsIgnoreCase(OAuth2ParameterNames.CLIENT_SECRET)
                        && !key.equalsIgnoreCase(OAuth2ParameterNames.STATE)
                        && !key.equalsIgnoreCase("code_challenge")
                        && !key.equalsIgnoreCase("code_verifier")) {

                    addMultiValue(attributes, "request.query." + key, value);
                }
            });

            addHeaders(
                    attributes,
                    "request",
                    () -> request.getHeaderNames().asIterator(),
                    (v) -> () -> request.getHeaders(v).asIterator(),
                    Set.of(
                            "cookie",
                            "authorization"
                    )
            );

            return attributes;
        }

        private static Map<String, String> buildResponseAttributes(HttpServletResponse response) {
            final Map<String, String> attributes = new HashMap<>();
            attributes.put("response.status_code", Integer.toString(response.getStatus()));
            addHeaders(
                    attributes,
                    "response",
                    response.getHeaderNames(),
                    response::getHeaders,
                    Set.of(
                            "set-cookie",
                            "pragma",
                            "x-xss-protection",
                            "x-content-type-options",
                            "expires",
                            "cache-control",
                            "x-frame-options"
                    )
            );

            return attributes;
        }

        private static void addHeaders(Map<String, String> map, String prefix, Iterable<String> names, Function<String, Iterable<String>> getHeaders, Set<String> ignore) {
            for (String header : names) {
                if (!ignore.contains(header.toLowerCase())) {
                    final List<String> values = new ArrayList<>();
                    for (String value : getHeaders.apply(header)) {
                        values.add(value);
                    }

                    addMultiValue(map, prefix + ".header." + header, values);
                }
            }
        }

        private static void addMultiValue(Map<String, String> map, String key, List<String> values) {
            if (values.isEmpty()) {
                map.put(key, "");
            } else if (values.size() == 1) {
                map.put(key, values.getFirst());
            } else {
                for (int i = 0; i < values.size(); i++) {
                    map.put(key + "." + i, values.get(i));
                }
            }
        }
    }
}
