package com.gw2auth.oauth2.server.adapt;

import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

public class CustomOAuth2AuthorizationCodeRequestAuthenticationProvider implements AuthenticationProvider {

    private static final ThreadLocal<Map<String, Object>> CONTEXT_MAP = new ThreadLocal<>();

    private final OAuth2AuthorizationCodeRequestAuthenticationProvider delegate;
    private final OAuth2AuthorizationService oAuth2AuthorizationService;

    public CustomOAuth2AuthorizationCodeRequestAuthenticationProvider(RegisteredClientRepository registeredClientRepository, OAuth2AuthorizationService authorizationService, OAuth2AuthorizationConsentService authorizationConsentService) {
        this.delegate = new OAuth2AuthorizationCodeRequestAuthenticationProvider(registeredClientRepository, authorizationService, authorizationConsentService);
        this.oAuth2AuthorizationService = authorizationService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        final OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication = (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;

        final Map<String, Object> map = new HashMap<>();
        map.put("SELF", this);
        map.put("TOKEN", authorizationCodeRequestAuthentication);
        map.put("VALUES", new HashMap<>());

        CONTEXT_MAP.set(map);
        try {
            return this.delegate.authenticate(authorizationCodeRequestAuthentication);
        } finally {
            CONTEXT_MAP.remove();
        }
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return this.delegate.supports(aClass);
    }

    private static <T> T getContextValue(String key) {
        return Optional.ofNullable(CONTEXT_MAP.get()).map((v) -> v.get(key)).map((v) -> (T) v).orElse(null);
    }

    public static Stream<Map.Entry<String, Object>> getAdditionalParameters() {
        final OAuth2AuthorizationCodeRequestAuthenticationToken contextToken = getContextValue("TOKEN");
        if (contextToken == null) {
            throw new IllegalStateException();
        }

        return contextToken.getAdditionalParameters().entrySet().stream();
    }

    public static boolean isInCodeRequest() {
        return CONTEXT_MAP.get() != null;
    }

    public static boolean isInConsentContext() {
        final OAuth2AuthorizationCodeRequestAuthenticationToken contextToken = getContextValue("TOKEN");
        return contextToken != null && contextToken.isConsent();
    }

    public static Set<String> getRequestedScopes() {
        final OAuth2AuthorizationCodeRequestAuthenticationToken contextToken = getContextValue("TOKEN");
        if (contextToken == null) {
            throw new IllegalStateException();
        }

        if (isInConsentContext()) {
            final CustomOAuth2AuthorizationCodeRequestAuthenticationProvider self = getContextValue("SELF");
            final OAuth2Authorization authorization = self.oAuth2AuthorizationService.findByToken(contextToken.getState(), new OAuth2TokenType(OAuth2ParameterNames.STATE));
            if (authorization == null) {
                throw new IllegalStateException();
            }

            final OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
            if (authorizationRequest == null) {
                throw new IllegalStateException();
            }

            return authorizationRequest.getScopes();
        } else {
            return contextToken.getScopes();
        }
    }

    public static void putValue(String key, Object value) {
        final Map<String, Object> values = getContextValue("VALUES");
        if (values == null) {
            throw new IllegalStateException();
        }

        values.put(key, value);
    }

    public static <T> Optional<T> getValue(String key) {
        final Map<String, Object> values = getContextValue("VALUES");
        if (values == null) {
            throw new IllegalStateException();
        }

        return Optional.ofNullable(values.get(key)).map((v) -> (T) v);
    }

    public static OAuth2AuthorizationCodeRequestAuthenticationException error(OAuth2Error error) {
        final OAuth2AuthorizationCodeRequestAuthenticationToken contextToken = getContextValue("TOKEN");
        if (contextToken == null) {
            throw new IllegalStateException();
        }

        return new OAuth2AuthorizationCodeRequestAuthenticationException(error, contextToken);
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
