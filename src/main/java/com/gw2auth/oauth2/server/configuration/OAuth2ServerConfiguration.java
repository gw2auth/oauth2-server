package com.gw2auth.oauth2.server.configuration;

import com.gw2auth.oauth2.server.adapt.CustomOAuth2AuthorizationCodeRequestAuthenticationProvider;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;

@Configuration
public class OAuth2ServerConfiguration {

    public static final String OAUTH2_CONSENT_PAGE = "/oauth2/consent";

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain oauth2ServerHttpSecurityFilterChain(HttpSecurity http, Customizer<OAuth2LoginConfigurer<HttpSecurity>> oauth2LoginCustomizer) throws Exception {
        final OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer<>();
        authorizationServerConfigurer.authorizationEndpoint((authorizationEndpoint) -> {
            authorizationEndpoint
                    .authenticationProvider(CustomOAuth2AuthorizationCodeRequestAuthenticationProvider.create(http))
                    .consentPage(OAUTH2_CONSENT_PAGE);
        });

        final RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

        // This configuration is only for requests matched by the RequestMatcher
        // (that is, only OAuth2 AUTHORIZATION requests -> requests where this application acts as a OAuth2 server, not a client)
        http
                .requestMatcher(endpointsMatcher)
                .authorizeRequests((auth) -> auth.anyRequest().authenticated())
                .csrf((csrf) -> csrf.ignoringRequestMatchers(endpointsMatcher))
                .oauth2Login(oauth2LoginCustomizer)
                .apply(authorizationServerConfigurer);

        return http.build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(@Value("${com.gw2auth.oauth2.keypair.id}") String keyPairId,
                                                @Value("${com.gw2auth.oauth2.keypair.path}") String keyPairPath) throws IOException, GeneralSecurityException {
        if (keyPairId.equals("generate")) {
            keyPairId = UUID.randomUUID().toString();
        }

        final KeyPair keyPair;

        if (keyPairPath.equals("generate")) {
            keyPair = generateRsaKey();
        } else {
            keyPair = loadRsaKey(keyPairPath, keyPairPath + ".pub");
        }

        final RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyID(keyPairId)
                .build();

        final JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    private static KeyPair loadRsaKey(String privateKeyPath, String publicKeyPath) throws IOException, GeneralSecurityException {
        final KeyFactory kf = KeyFactory.getInstance("RSA");
        final PrivateKey privateKey;
        final PublicKey publicKey;

        KeySpec spec = new PKCS8EncodedKeySpec(Files.readAllBytes(Paths.get(privateKeyPath)));
        privateKey = kf.generatePrivate(spec);

        spec = new X509EncodedKeySpec(Files.readAllBytes(Paths.get(publicKeyPath)));
        publicKey = kf.generatePublic(spec);

        return new KeyPair(publicKey, privateKey);
    }

    private static KeyPair generateRsaKey() throws GeneralSecurityException {
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        return keyPairGenerator.generateKeyPair();
    }

    @Bean
    public ProviderSettings providerSettings(@Value("${com.gw2auth.url}") String selfURL) {
        return ProviderSettings.builder().issuer(selfURL).build();
    }
}
