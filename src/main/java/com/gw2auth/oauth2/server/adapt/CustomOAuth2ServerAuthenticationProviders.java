package com.gw2auth.oauth2.server.adapt;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

public class CustomOAuth2ServerAuthenticationProviders {

    private static final Logger LOG = LoggerFactory.getLogger(CustomOAuth2ServerAuthenticationProviders.class);
    private static final ThreadLocal<@Nullable Context> CONTEXT = new ThreadLocal<>();

    private static Optional<Context> getContext() {
        return Optional.ofNullable(CONTEXT.get());
    }

    public static Stream<Map.Entry<String, Object>> getAdditionalParameters() {
        return getContext()
                .map((v) -> v.token)
                .map((v) -> {
                    if (v instanceof OAuth2AuthorizationCodeRequestAuthenticationToken token) {
                        return token.getAdditionalParameters();
                    } else if (v instanceof OAuth2AuthorizationConsentAuthenticationToken token) {
                        return token.getAdditionalParameters();
                    } else {
                        throw new IllegalStateException();
                    }
                })
                .orElseThrow(IllegalStateException::new)
                .entrySet()
                .stream();
    }

    public static boolean isInCodeRequest() {
        // might also be consent context, but current code relies on this behavior
        return getContext().isPresent();
    }

    public static boolean isInConsentContext() {
        return getContext()
                .map((v) -> v.token)
                .filter(OAuth2AuthorizationConsentAuthenticationToken.class::isInstance)
                .isPresent();
    }

    public static Optional<OAuth2AuthorizationCodeRequestAuthenticationToken> getCodeRequest() {
        return getContext()
                .map((v) -> v.token)
                .filter(OAuth2AuthorizationCodeRequestAuthenticationToken.class::isInstance)
                .map(OAuth2AuthorizationCodeRequestAuthenticationToken.class::cast);
    }

    public static Set<String> getRequestedScopes() {
        final Context context = getContext().orElseThrow(IllegalStateException::new);

        if (context.token instanceof OAuth2AuthorizationConsentAuthenticationToken token) {
            final OAuth2Authorization authorization = context.self.oauth2AuthorizationService.findByToken(token.getState(), new OAuth2TokenType(OAuth2ParameterNames.STATE));
            if (authorization == null) {
                throw new IllegalStateException();
            }

            final OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
            if (authorizationRequest == null) {
                throw new IllegalStateException();
            }

            return authorizationRequest.getScopes();
        } else if (context.token instanceof OAuth2AuthorizationCodeRequestAuthenticationToken token) {
            return token.getScopes();
        } else {
            throw new IllegalStateException();
        }
    }

    public static void putValue(String key, Object value) {
        final Map<String, Object> values = getContext()
                .map((v) -> v.values)
                .orElse(null);

        if (values == null) {
            throw new IllegalStateException();
        }

        values.put(key, value);
    }

    public static <T> Optional<T> getValue(String key) {
        final Map<String, Object> values = getContext()
                .map((v) -> v.values)
                .orElse(null);

        if (values == null) {
            throw new IllegalStateException();
        }

        return Optional.ofNullable(values.get(key)).map((v) -> (T) v);
    }

    public static OAuth2AuthorizationCodeRequestAuthenticationException error(OAuth2Error error) {
        final Context context = getContext().orElseThrow(IllegalStateException::new);
        final OAuth2AuthorizationCodeRequestAuthenticationToken codeRequestAuthenticationToken;

        if (context.token instanceof OAuth2AuthorizationCodeRequestAuthenticationToken token) {
            codeRequestAuthenticationToken = token;
        } else if (context.token instanceof OAuth2AuthorizationConsentAuthenticationToken token) {
            codeRequestAuthenticationToken = codeRequestTokenForConsentToken(context.self, token);
        } else {
            throw new IllegalStateException();
        }

        return new OAuth2AuthorizationCodeRequestAuthenticationException(error, codeRequestAuthenticationToken);
    }

    private static OAuth2AuthorizationCodeRequestAuthenticationToken codeRequestTokenForConsentToken(AbstractOAuth2AuthenticationProvider self, OAuth2AuthorizationConsentAuthenticationToken token) {
        final OAuth2Authorization authorization = self.oauth2AuthorizationService.findByToken(token.getState(), new OAuth2TokenType(OAuth2ParameterNames.STATE));
        final RegisteredClient registeredClient = self.registeredClientRepository.findByClientId(token.getClientId());
        final OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
        final String redirectUri = resolveRedirectUri(authorizationRequest, registeredClient);
        final String state = authorizationRequest != null ? authorizationRequest.getState() : token.getState();
        final Set<String> requestedScopes = authorizationRequest != null ? authorizationRequest.getScopes() : token.getScopes();

        return new OAuth2AuthorizationCodeRequestAuthenticationToken(
                token.getAuthorizationUri(),
                token.getClientId(),
                (Authentication) token.getPrincipal(),
                redirectUri,
                state,
                requestedScopes,
                null
        );
    }

    private static @Nullable String resolveRedirectUri(@Nullable OAuth2AuthorizationRequest authorizationRequest, @Nullable RegisteredClient registeredClient) {
        if (authorizationRequest != null && StringUtils.hasText(authorizationRequest.getRedirectUri())) {
            return authorizationRequest.getRedirectUri();
        }
        if (registeredClient != null) {
            return registeredClient.getRedirectUris().iterator().next();
        }
        return null;
    }

    public static AuthenticationProvider createCodeRequestAuthenticationProvider(HttpSecurity http) {
        return new CustomOAuth2AuthorizationCodeRequestAuthenticationProvider(
                getRegisteredClientRepository(http),
                getAuthorizationService(http),
                getAuthorizationConsentService(http)
        );
    }

    public static AuthenticationProvider createConsentAuthenticationProvider(HttpSecurity http) {
        return new CustomOAuth2AuthorizationConsentAuthenticationProvider(
                getRegisteredClientRepository(http),
                getAuthorizationService(http),
                getAuthorizationConsentService(http)
        );
    }

    private static <B extends HttpSecurityBuilder<B>> RegisteredClientRepository getRegisteredClientRepository(B builder) {
        RegisteredClientRepository registeredClientRepository = builder.<@Nullable RegisteredClientRepository>getSharedObject(RegisteredClientRepository.class);
        if (registeredClientRepository == null) {
            registeredClientRepository = getBean(builder, RegisteredClientRepository.class);
            builder.setSharedObject(RegisteredClientRepository.class, registeredClientRepository);
        }
        return registeredClientRepository;
    }

    private static <B extends HttpSecurityBuilder<B>> OAuth2AuthorizationService getAuthorizationService(B builder) {
        OAuth2AuthorizationService authorizationService = builder.<@Nullable OAuth2AuthorizationService>getSharedObject(OAuth2AuthorizationService.class);
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
        OAuth2AuthorizationConsentService authorizationConsentService = builder.<@Nullable OAuth2AuthorizationConsentService>getSharedObject(OAuth2AuthorizationConsentService.class);
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

    private static <B extends HttpSecurityBuilder<B>, T> @Nullable T getOptionalBean(B builder, Class<T> type) {
        Map<String, T> beansMap = BeanFactoryUtils.beansOfTypeIncludingAncestors(
                builder.getSharedObject(ApplicationContext.class), type);
        if (beansMap.size() > 1) {
            throw new NoUniqueBeanDefinitionException(type, beansMap.size(),
                    "Expected single matching bean of type '" + type.getName() + "' but found " +
                            beansMap.size() + ": " + StringUtils.collectionToCommaDelimitedString(beansMap.keySet()));
        }
        return (!beansMap.isEmpty() ? beansMap.values().iterator().next() : null);
    }

    private static abstract class AbstractOAuth2AuthenticationProvider implements AuthenticationProvider {

        private final AuthenticationProvider delegate;
        private final RegisteredClientRepository registeredClientRepository;
        private final OAuth2AuthorizationService oauth2AuthorizationService;

        private AbstractOAuth2AuthenticationProvider(AuthenticationProvider delegate, RegisteredClientRepository registeredClientRepository, OAuth2AuthorizationService oauth2AuthorizationService) {
            this.delegate = delegate;
            this.registeredClientRepository = registeredClientRepository;
            this.oauth2AuthorizationService = oauth2AuthorizationService;
        }

        protected Authentication authenticate(Authentication authentication, Context context) throws AuthenticationException {
            final Context prev = CONTEXT.get();
            CONTEXT.set(context);
            try {
                return this.delegate.authenticate(authentication);
            } finally {
                if (prev == null) {
                    CONTEXT.remove();
                } else {
                    CONTEXT.set(prev);
                }
            }
        }

        @Override
        public boolean supports(Class<?> aClass) {
            return this.delegate.supports(aClass);
        }
    }

    private static class CustomOAuth2AuthorizationCodeRequestAuthenticationProvider extends AbstractOAuth2AuthenticationProvider {

        private CustomOAuth2AuthorizationCodeRequestAuthenticationProvider(RegisteredClientRepository registeredClientRepository, OAuth2AuthorizationService authorizationService, OAuth2AuthorizationConsentService authorizationConsentService) {
            super(
                    new OAuth2AuthorizationCodeRequestAuthenticationProvider(registeredClientRepository, authorizationService, authorizationConsentService),
                    registeredClientRepository,
                    authorizationService
            );
        }

        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            final OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication = (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;
            try {
                return authenticate(authorizationCodeRequestAuthentication, new Context(this, authorizationCodeRequestAuthentication, new HashMap<>()));
            } catch (Exception e) {
                LOG.warn("caught exception during oauth2 authenticate (oauth2 code request)", e);
                throw e;
            }
        }
    }

    private static class CustomOAuth2AuthorizationConsentAuthenticationProvider extends AbstractOAuth2AuthenticationProvider {

        private CustomOAuth2AuthorizationConsentAuthenticationProvider(RegisteredClientRepository registeredClientRepository, OAuth2AuthorizationService authorizationService, OAuth2AuthorizationConsentService authorizationConsentService) {
            super(
                    new OAuth2AuthorizationConsentAuthenticationProvider(registeredClientRepository, authorizationService, authorizationConsentService),
                    registeredClientRepository,
                    authorizationService
            );
        }

        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            final OAuth2AuthorizationConsentAuthenticationToken authorizationConsentAuthentication = (OAuth2AuthorizationConsentAuthenticationToken) authentication;
            try {
                return authenticate(authorizationConsentAuthentication, new Context(this, authorizationConsentAuthentication, new HashMap<>()));
            } catch (Exception e) {
                LOG.warn("caught exception during oauth2 authenticate (oauth2 consent)", e);
                throw e;
            }
        }
    }

    private record Context(AbstractOAuth2AuthenticationProvider self, AbstractAuthenticationToken token, Map<String, Object> values) {}
}
