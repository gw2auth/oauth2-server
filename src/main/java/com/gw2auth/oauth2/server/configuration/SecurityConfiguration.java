package com.gw2auth.oauth2.server.configuration;

import com.gw2auth.oauth2.server.adapt.Gw2AuthSecurityContextRepository;
import com.gw2auth.oauth2.server.adapt.Gw2AuthSessionDeletionLogoutHandler;
import com.gw2auth.oauth2.server.adapt.S3AuthorizationRequestRepository;
import com.gw2auth.oauth2.server.service.account.AccountFederationSession;
import com.gw2auth.oauth2.server.service.account.AccountService;
import com.gw2auth.oauth2.server.service.security.Gw2AuthInternalJwtConverter;
import com.gw2auth.oauth2.server.service.user.Gw2AuthLoginUser;
import com.gw2auth.oauth2.server.service.user.Gw2AuthTokenUserService;
import com.gw2auth.oauth2.server.util.Constants;
import com.gw2auth.oauth2.server.util.CookieHelper;
import com.gw2auth.oauth2.server.util.DynamicProxy;
import com.gw2auth.oauth2.server.util.JWKHelper;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer;
import org.springframework.security.config.annotation.web.configurers.SecurityContextConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.savedrequest.CookieRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import software.amazon.awssdk.services.s3.S3Client;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Bean
    public Gw2AuthInternalJwtConverter gw2AuthInternalJwtConverter(@Value("${com.gw2auth.session.priv.id}") String privateKeyId,
                                                                   @Value("${com.gw2auth.session.priv.path}") String privateKeyPath,
                                                                   @Value("${com.gw2auth.session.pub1.id}") String pub1KeyId,
                                                                   @Value("${com.gw2auth.session.pub1.path}") String pub1KeyPath,
                                                                   @Value("${com.gw2auth.session.pub2.id}") String pub2KeyId,
                                                                   @Value("${com.gw2auth.session.pub2.path}") String pub2KeyPath,
                                                                   Environment environment) throws Exception {

        if (pub1KeyId.equals(pub2KeyId)) {
            throw new IllegalStateException("key ids are not unique");
        }

        final boolean isTest = environment.acceptsProfiles(Profiles.of("test"));
        final PrivateKey privateKey;
        final PublicKey privateKeyMatchingPublic;

        if (privateKeyPath.equals("generate")) {
            if (!isTest) {
                throw new IllegalStateException("key generation only enabled for tests");
            }

            final KeyPair keyPair = JWKHelper.generateRsaKeyPair();
            privateKey = keyPair.getPrivate();
            privateKeyMatchingPublic = keyPair.getPublic();
        } else {
            privateKey = JWKHelper.loadRsaPrivateKey(privateKeyPath);
            privateKeyMatchingPublic = null;
        }

        final Map<String, String> pubKeyPaths = Map.of(
                pub1KeyId, pub1KeyPath,
                pub2KeyId, pub2KeyPath
        );
        final Map<String, RSAPublicKey> publicKeys = new HashMap<>();

        for (Map.Entry<String, String> entry : pubKeyPaths.entrySet()) {
            final String keyId = entry.getKey();
            final String keyPath = entry.getValue();
            final PublicKey publicKey;

            if (keyPath.equals("generate")) {
                if (!isTest) {
                    throw new IllegalStateException("key generation only enabled for tests");
                }

                if (keyId.equals(privateKeyId)) {
                    publicKey = Objects.requireNonNull(privateKeyMatchingPublic);
                } else {
                    publicKey = JWKHelper.generateRsaKeyPair().getPublic();
                }
            } else {
                publicKey = JWKHelper.loadRsaPublicKey(keyPath);
            }

            publicKeys.put(keyId, (RSAPublicKey) publicKey);
        }

        return new Gw2AuthInternalJwtConverter(privateKeyId, (RSAPrivateKey) privateKey, publicKeys);
    }

    @Bean
    public RequestCache requestCache() {
        return new CookieRequestCache();
    }

    @Bean
    public Customizer<SecurityContextConfigurer<HttpSecurity>> securityContextCustomizer(Gw2AuthTokenUserService gw2AuthTokenUserService) {
        return (sc) -> sc.securityContextRepository(new Gw2AuthSecurityContextRepository(gw2AuthTokenUserService));
    }

    @Bean
    public Customizer<RequestCacheConfigurer<HttpSecurity>> requestCacheCustomizer(RequestCache requestCache) {
        return (rc) -> rc.requestCache(requestCache);
    }

    @Bean
    public Customizer<OAuth2LoginConfigurer<HttpSecurity>> oauth2LoginCustomizer(@Qualifier("oauth2-authorization-s3-client") S3Client s3,
                                                                                 @Value("${com.gw2auth.oauth2.client.s3.bucket}") String bucket,
                                                                                 @Value("${com.gw2auth.oauth2.client.s3.prefix}") String prefix,
                                                                                 Gw2AuthInternalJwtConverter jwtConverter,
                                                                                 RequestCache requestCache) {

        final AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository = new S3AuthorizationRequestRepository(
                DynamicProxy.create(s3, S3Client.class, S3AuthorizationRequestRepository.MinimalS3Client.class),
                bucket,
                prefix
        );
        final SavedRequestAwareAuthenticationSuccessHandler delegate = new SavedRequestAwareAuthenticationSuccessHandler();
        delegate.setRequestCache(requestCache);
        delegate.setDefaultTargetUrl("/account");

        return (oauth2) -> {
            oauth2
                    .loginPage("/login")
                    .loginProcessingUrl("/auth/oauth2/code/*")
                    .authorizationEndpoint(authEndpoint -> {
                        authEndpoint
                                .baseUri("/auth/oauth2/authorization")
                                .authorizationRequestRepository(authorizationRequestRepository);
                    })
                    .successHandler((request, response, authentication) -> {
                        final Object principal = authentication.getPrincipal();
                        if (principal instanceof Gw2AuthLoginUser user) {
                            final AccountFederationSession session = user.session();
                            final byte[] encryptionKey = user.encryptionKey();

                            final Jwt jwt = jwtConverter.writeJWT(session.id(), encryptionKey, session.expirationTime());
                            CookieHelper.addCookie(request, response, Constants.ACCESS_TOKEN_COOKIE_NAME, jwt.getTokenValue(), jwt.getExpiresAt());
                        }

                        delegate.onAuthenticationSuccess(request, response, authentication);
                        requestCache.removeRequest(request, response);
                    });
        };
    }

    @Bean
    public Customizer<CsrfConfigurer<HttpSecurity>> csrfCustomizer() {
        // https://docs.spring.io/spring-security/reference/5.8/migration/servlet/exploits.html#_i_am_using_angularjs_or_another_javascript_framework
        // https://docs.spring.io/spring-security/reference/5.8/migration/servlet/exploits.html#servlet-opt-in-defer-loading-csrf-token
        final CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
        requestHandler.setCsrfRequestAttributeName(null);

        return (csrf) -> csrf.csrfTokenRequestHandler(requestHandler).csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
    }

    @Bean("auth-request-matcher")
    public RequestMatcher authRequestMatcher() {
        return new AntPathRequestMatcher("/auth/**");
    }

    @Bean
    @Order(1)
    public SecurityFilterChain frontendHttpSecurityFilterChain(HttpSecurity http,
                                                               AccountService accountService,
                                                               @Qualifier("auth-request-matcher") RequestMatcher requestMatcher,
                                                               Customizer<SecurityContextConfigurer<HttpSecurity>> securityContextCustomizer,
                                                               Customizer<RequestCacheConfigurer<HttpSecurity>> requestCacheCustomizer,
                                                               Customizer<OAuth2LoginConfigurer<HttpSecurity>> oauth2LoginCustomizer,
                                                               Customizer<CsrfConfigurer<HttpSecurity>> csrfCustomizer) throws Exception {

        final LogoutHandler logoutHandler = new Gw2AuthSessionDeletionLogoutHandler(accountService);

        http
                .securityMatcher(requestMatcher)
                .csrf(csrfCustomizer)
                .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .securityContext(securityContextCustomizer)
                .requestCache(requestCacheCustomizer)
                .oauth2Login(oauth2LoginCustomizer)
                .logout((logout) -> {
                    logout
                            .logoutUrl(Constants.LOGOUT_URL)
                            .deleteCookies(Constants.ACCESS_TOKEN_COOKIE_NAME)
                            .addLogoutHandler(logoutHandler)
                            .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler());
                });

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
                                                          Customizer<SecurityContextConfigurer<HttpSecurity>> securityContextCustomizer) throws Exception {

        http
                .securityMatcher(requestMatcher)
                .authorizeHttpRequests((auth) -> {
                    auth
                            .requestMatchers("/api/authinfo", "/api/application/summary").permitAll()
                            .anyRequest().authenticated();
                })
                .csrf(csrfCustomizer)
                .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .securityContext(securityContextCustomizer);

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
                .securityMatcher(requestMatcher)
                .authorizeHttpRequests((auth) -> auth.anyRequest().permitAll());

        return http.build();
    }
}
