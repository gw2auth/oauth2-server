package com.gw2auth.oauth2.server.adapt;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.StringUtils;

import java.util.Map;
import java.util.stream.Stream;

public class CustomOAuth2AuthorizationCodeRequestAuthenticationProvider implements AuthenticationProvider {

    private static final ThreadLocal<Map<String, Object>> ADDITIONAL_PARAMETERS = new ThreadLocal<>();
    private static final ThreadLocal<Boolean> IS_CONSENT_CONTEXT = new ThreadLocal<>();

    private final OAuth2AuthorizationCodeRequestAuthenticationProvider delegate;

    public CustomOAuth2AuthorizationCodeRequestAuthenticationProvider(RegisteredClientRepository registeredClientRepository, OAuth2AuthorizationService authorizationService, OAuth2AuthorizationConsentService authorizationConsentService) {
        this.delegate = new OAuth2AuthorizationCodeRequestAuthenticationProvider(registeredClientRepository, authorizationService, authorizationConsentService);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        final OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication = (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;
        final Map<String, Object> additionalParameters = authorizationCodeRequestAuthentication.getAdditionalParameters();
        final boolean isConsentContext = authorizationCodeRequestAuthentication.isConsent();

        ADDITIONAL_PARAMETERS.set(additionalParameters);
        IS_CONSENT_CONTEXT.set(isConsentContext);
        try {
            return this.delegate.authenticate(authorizationCodeRequestAuthentication);
        } finally {
            ADDITIONAL_PARAMETERS.remove();
            IS_CONSENT_CONTEXT.remove();
        }
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return this.delegate.supports(aClass);
    }

    public static Stream<Map.Entry<String, Object>> getAdditionalParameters() {
        final Map<String, Object> additionalParameters = ADDITIONAL_PARAMETERS.get();
        if (additionalParameters == null) {
            throw new IllegalStateException();
        }

        return additionalParameters.entrySet().stream();
    }

    public static boolean isInConsentContext() {
        final Boolean value = IS_CONSENT_CONTEXT.get();
        return value != null && value;
    }

    public static CustomOAuth2AuthorizationCodeRequestAuthenticationProvider create(HttpSecurity http) {
        return new CustomOAuth2AuthorizationCodeRequestAuthenticationProvider(
                getRegisteredClientRepository(http),
                getAuthorizationService(http),
                getAuthorizationConsentService(http)
        );
    }

    private static <B extends HttpSecurityBuilder<B>> RegisteredClientRepository getRegisteredClientRepository(B builder) {
        RegisteredClientRepository registeredClientRepository = builder.getSharedObject(RegisteredClientRepository.class);
        if (registeredClientRepository == null) {
            registeredClientRepository = getBean(builder, RegisteredClientRepository.class);
            builder.setSharedObject(RegisteredClientRepository.class, registeredClientRepository);
        }
        return registeredClientRepository;
    }

    private static <B extends HttpSecurityBuilder<B>> OAuth2AuthorizationService getAuthorizationService(B builder) {
        OAuth2AuthorizationService authorizationService = builder.getSharedObject(OAuth2AuthorizationService.class);
        if (authorizationService == null) {
            authorizationService = getOptionalBean(builder, OAuth2AuthorizationService.class);
            if (authorizationService == null) {
                authorizationService = new InMemoryOAuth2AuthorizationService();
            }
            builder.setSharedObject(OAuth2AuthorizationService.class, authorizationService);
        }
        return authorizationService;
    }

    private static <B extends HttpSecurityBuilder<B>> OAuth2AuthorizationConsentService getAuthorizationConsentService(B builder) {
        OAuth2AuthorizationConsentService authorizationConsentService = builder.getSharedObject(OAuth2AuthorizationConsentService.class);
        if (authorizationConsentService == null) {
            authorizationConsentService = getOptionalBean(builder, OAuth2AuthorizationConsentService.class);
            if (authorizationConsentService == null) {
                authorizationConsentService = new InMemoryOAuth2AuthorizationConsentService();
            }
            builder.setSharedObject(OAuth2AuthorizationConsentService.class, authorizationConsentService);
        }
        return authorizationConsentService;
    }

    private static <B extends HttpSecurityBuilder<B>, T> T getBean(B builder, Class<T> type) {
        return builder.getSharedObject(ApplicationContext.class).getBean(type);
    }

    private static <B extends HttpSecurityBuilder<B>, T> T getOptionalBean(B builder, Class<T> type) {
        Map<String, T> beansMap = BeanFactoryUtils.beansOfTypeIncludingAncestors(
                builder.getSharedObject(ApplicationContext.class), type);
        if (beansMap.size() > 1) {
            throw new NoUniqueBeanDefinitionException(type, beansMap.size(),
                    "Expected single matching bean of type '" + type.getName() + "' but found " +
                            beansMap.size() + ": " + StringUtils.collectionToCommaDelimitedString(beansMap.keySet()));
        }
        return (!beansMap.isEmpty() ? beansMap.values().iterator().next() : null);
    }
}
