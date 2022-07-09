package com.gw2auth.oauth2.server.configuration;

import com.amazonaws.services.s3.AmazonS3;
import com.gw2auth.oauth2.server.adapt.*;
import com.gw2auth.oauth2.server.service.account.AccountFederationSession;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.user.Gw2AuthLoginUser;
import com.gw2auth.oauth2.server.service.user.Gw2AuthTokenUserService;
import com.gw2auth.oauth2.server.util.Constants;
import com.gw2auth.oauth2.server.util.CookieHelper;
import com.gw2auth.oauth2.server.util.JWKHelper;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer;
import org.springframework.security.config.annotation.web.configurers.SecurityContextConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.savedrequest.CookieRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Bean
    public Gw2AuthInternalJwtConverter gw2AuthInternalJwtConverter(@Value("${com.gw2auth.session.key.id}") String sessionKeyId,
                                                                   @Value("${com.gw2auth.session.key.path}") String sessionKeyPath) throws Exception {

        if (sessionKeyId.equals("generate")) {
            sessionKeyId = UUID.randomUUID().toString();
        }

        final KeyPair keyPair;
        if (sessionKeyPath.equals("generate")) {
            keyPair = JWKHelper.generateRsaKeyPair();
        } else {
            keyPair = JWKHelper.loadRsaKeyPair(sessionKeyPath, sessionKeyPath + ".pub");
        }

        return new Gw2AuthInternalJwtConverter(sessionKeyId, (RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate());
    }

    @Bean
    public RequestCache requestCache() {
        return new CookieRequestCache();
    }

    @Bean
    public Customizer<SecurityContextConfigurer<HttpSecurity>> securityContextCustomizer() {
        return (sc) -> sc.securityContextRepository(new RequestAttributeSecurityContextRepository());
    }

    @Bean
    public Customizer<RequestCacheConfigurer<HttpSecurity>> requestCacheCustomizer(RequestCache requestCache) {
        return (rc) -> rc.requestCache(requestCache);
    }

    @Bean
    public Customizer<OAuth2LoginConfigurer<HttpSecurity>> oauth2LoginCustomizer(@Qualifier("oauth2-authorization-s3-client") AmazonS3 s3,
                                                                                 @Value("${com.gw2auth.oauth2.client.s3.bucket}") String bucket,
                                                                                 @Value("${com.gw2auth.oauth2.client.s3.prefix}") String prefix,
                                                                                 Gw2AuthInternalJwtConverter authenticationSerializer,
                                                                                 RequestCache requestCache) {

        final AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository = new S3AuthorizationRequestRepository(s3, bucket, prefix);
        final SavedRequestAwareAuthenticationSuccessHandler delegate = new SavedRequestAwareAuthenticationSuccessHandler();
        delegate.setRequestCache(requestCache);
        delegate.setDefaultTargetUrl("/account");

        return (oauth2) -> {
            oauth2
                    .loginPage("/login")
                    .authorizationEndpoint(authEndpoint -> authEndpoint.authorizationRequestRepository(authorizationRequestRepository))
                    .successHandler((request, response, authentication) -> {
                        final Object principal = authentication.getPrincipal();
                        if (principal instanceof Gw2AuthLoginUser user) {
                            final AccountFederationSession session = user.session();
                            final Jwt jwt = authenticationSerializer.writeJWT(session.id(), session.creationTime(), session.expirationTime());
                            CookieHelper.addCookie(request, response, Constants.ACCESS_TOKEN_COOKIE_NAME, jwt.getTokenValue(), jwt.getExpiresAt());
                        }

                        delegate.onAuthenticationSuccess(request, response, authentication);
                    });
        };
    }

    @Bean
    public Customizer<OAuth2ResourceServerConfigurer<HttpSecurity>> oauth2ResourceServerCustomizer(Gw2AuthTokenUserService gw2AuthTokenUserService) {
        return (oauth2) -> {
            oauth2
                    .bearerTokenResolver(new CookieBearerTokenResolver(Constants.ACCESS_TOKEN_COOKIE_NAME))
                    .authenticationManagerResolver(new Gw2AuthAuthenticationManagerResolver(gw2AuthTokenUserService));
        };
    }

    @Bean
    public Customizer<CsrfConfigurer<HttpSecurity>> csrfCustomizer() {
        return (csrf) -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
    }

    @Bean("frontend-request-matcher")
    public RequestMatcher frontendRequestMatcher(@Qualifier("resources-request-matcher") RequestMatcher resourcesRequestMatcher,
                                                 @Qualifier("api-request-matcher") RequestMatcher apiRequestMatcher,
                                                 @Qualifier("oidc-server-request-matcher") RequestMatcher oidcServerRequestMatcher,
                                                 @Qualifier("oauth2-server-request-matcher") RequestMatcher oauth2ServerRequestMatcher,
                                                 @Qualifier("actuator-request-matcher") Optional<RequestMatcher> actuatorRequestMatcher) {

        final List<RequestMatcher> requestMatchers = new ArrayList<>(List.of(resourcesRequestMatcher, apiRequestMatcher, oidcServerRequestMatcher, oauth2ServerRequestMatcher));
        actuatorRequestMatcher.ifPresent(requestMatchers::add);

        return new NegatedRequestMatcher(new OrRequestMatcher(requestMatchers));
    }

    @Bean
    @Order(3)
    public SecurityFilterChain frontendHttpSecurityFilterChain(HttpSecurity http,
                                                               AccountService accountService,
                                                               @Qualifier("frontend-request-matcher") RequestMatcher requestMatcher,
                                                               Customizer<SecurityContextConfigurer<HttpSecurity>> securityContextCustomizer,
                                                               Customizer<RequestCacheConfigurer<HttpSecurity>> requestCacheCustomizer,
                                                               Customizer<OAuth2LoginConfigurer<HttpSecurity>> oauth2LoginCustomizer,
                                                               Customizer<OAuth2ResourceServerConfigurer<HttpSecurity>> oauth2ResourceServerCustomizer,
                                                               Customizer<CsrfConfigurer<HttpSecurity>> csrfCustomizer) throws Exception {

        final LogoutHandler logoutHandler = new Gw2AuthSessionDeletionLogoutHandler(accountService);

        http
                .requestMatcher(requestMatcher)
                .authorizeRequests((auth) -> auth.antMatchers("/", "/login", "/privacy-policy", "/legal", "/faq").permitAll().anyRequest().authenticated())
                .csrf(csrfCustomizer)
                .headers((headers) -> {
                    headers
                            .frameOptions().deny()
                            .contentSecurityPolicy((csp) -> csp.policyDirectives(String.join("; ",
                                    "default-src 'self'",
                                    "connect-src 'self' https://api.guildwars2.com",
                                    "script-src 'self' 'unsafe-inline'",
                                    "style-src 'self' 'unsafe-inline'",
                                    "img-src 'self' https://icons-gw2.darthmaim-cdn.com/ data:",
                                    "frame-src https://www.youtube.com/embed/"
                            )));
                })
                .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .securityContext(securityContextCustomizer)
                .requestCache(requestCacheCustomizer)
                .oauth2Login(oauth2LoginCustomizer)
                .oauth2ResourceServer(oauth2ResourceServerCustomizer)
                .logout((logout) -> {
                    logout
                            .deleteCookies(Constants.ACCESS_TOKEN_COOKIE_NAME)
                            .addLogoutHandler(logoutHandler)
                            .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler());
                });

        return http.build();
    }

    @Bean("resources-request-matcher")
    public RequestMatcher resourcesRequestMatcher() {
        return new OrRequestMatcher(
                new AntPathRequestMatcher("/**/*.css"),
                new AntPathRequestMatcher("/**/*.js"),
                new AntPathRequestMatcher("/assets/**"),
                new AntPathRequestMatcher("/favicon.ico"),
                new AntPathRequestMatcher("/robots.txt")
        );
    }

    @Bean
    @Order(2)
    public SecurityFilterChain resourcesSecurityFilterChain(HttpSecurity http, @Qualifier("resources-request-matcher") RequestMatcher requestMatcher) throws Exception {
        http
                .requestMatcher(requestMatcher)
                .authorizeRequests((auth) -> auth.anyRequest().permitAll());

        return http.build();
    }

    @Bean("api-request-matcher")
    public RequestMatcher apiRequestMatcher() {
        return new AntPathRequestMatcher("/api/**");
    }

    @Bean
    @Order(1)
    public SecurityFilterChain apiHttpSecurityFilterChain(HttpSecurity http,
                                                          @Qualifier("api-request-matcher") RequestMatcher requestMatcher,
                                                          Customizer<CsrfConfigurer<HttpSecurity>> csrfCustomizer,
                                                          Customizer<SecurityContextConfigurer<HttpSecurity>> securityContextCustomizer,
                                                          Customizer<OAuth2ResourceServerConfigurer<HttpSecurity>> oauth2ResourceServerCustomizer) throws Exception {

        http
                .requestMatcher(requestMatcher)
                .authorizeRequests((auth) -> {
                    auth
                            .antMatchers("/api/authinfo", "/api/application/summary").permitAll()
                            .anyRequest().authenticated();
                })
                .csrf(csrfCustomizer)
                .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .securityContext(securityContextCustomizer)
                .oauth2ResourceServer(oauth2ResourceServerCustomizer);

        return http.build();
    }

    @Bean("actuator-request-matcher")
    @ConditionalOnExpression("${management.endpoint.prometheus.enabled:false} && ${management.server.port:${server.port:8080}} != ${server.port:8080}")
    public RequestMatcher actuatorRequestMatcher() {
        return new AntPathRequestMatcher("/actuator/prometheus");
    }

    @Bean
    @ConditionalOnBean(name = "actuator-request-matcher")
    @Order(0)
    public SecurityFilterChain actuatorSecurityFilterChain(HttpSecurity http, @Qualifier("actuator-request-matcher") RequestMatcher requestMatcher) throws Exception {
        http
                .requestMatcher(requestMatcher)
                .authorizeRequests().anyRequest().permitAll();

        return http.build();
    }
}
