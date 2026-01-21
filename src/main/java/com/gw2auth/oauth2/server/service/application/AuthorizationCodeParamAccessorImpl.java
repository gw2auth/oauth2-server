package com.gw2auth.oauth2.server.service.application;

import com.gw2auth.oauth2.server.service.security.AuthenticationHelper;
import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

@Component
public class AuthorizationCodeParamAccessorImpl implements AuthorizationCodeParamAccessor {

    private static final String CUSTOM_ATTRIBUTE_PREFIX = AuthorizationCodeParamAccessorImpl.class.getName() + "::CUSTOM::";

    private final String requestAttributeName;
    private @Nullable RegisteredClientRepository registeredClientRepository;
    private @Nullable OAuth2AuthorizationService oauth2AuthorizationService;

    @Autowired
    public AuthorizationCodeParamAccessorImpl(@Qualifier("oauth2-authorization-authentication-request-attribute-name") String requestAttributeName) {
        this.requestAttributeName = Objects.requireNonNull(requestAttributeName);
        this.registeredClientRepository = null;
        this.oauth2AuthorizationService = null;
    }

    @Lazy
    @Autowired
    public void setRegisteredClientRepository(RegisteredClientRepository registeredClientRepository) {
        this.registeredClientRepository = Objects.requireNonNull(registeredClientRepository);
    }

    @Lazy
    @Autowired
    public void setOAuth2AuthorizationService(OAuth2AuthorizationService oauth2AuthorizationService) {
        this.oauth2AuthorizationService = Objects.requireNonNull(oauth2AuthorizationService);
    }

    @Override
    public Stream<Map.Entry<String, Object>> getAdditionalParameters() {
        return getAuthentication()
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

    @Override
    public boolean isInCodeRequest() {
        // might also be consent context, but current code relies on this behavior
        return getAuthentication()
                .filter((v) -> v instanceof OAuth2AuthorizationCodeRequestAuthenticationToken || v instanceof OAuth2AuthorizationConsentAuthenticationToken)
                .isPresent();
    }

    @Override
    public boolean isInConsentContext() {
        return getAuthentication()
                .filter(OAuth2AuthorizationConsentAuthenticationToken.class::isInstance)
                .isPresent();
    }

    @Override
    public Optional<OAuth2AuthorizationCodeRequestAuthenticationToken> getCodeRequest() {
        return getAuthentication()
                .filter(OAuth2AuthorizationCodeRequestAuthenticationToken.class::isInstance)
                .map(OAuth2AuthorizationCodeRequestAuthenticationToken.class::cast);
    }

    @Override
    public Set<String> getRequestedScopes() {
        if (this.oauth2AuthorizationService == null) {
            throw new IllegalStateException("OAuth2AuthorizationService is not initialized");
        }

        final Authentication authentication = getAuthentication().orElseThrow(IllegalStateException::new);

        if (authentication instanceof OAuth2AuthorizationConsentAuthenticationToken token) {
            final OAuth2Authorization authorization = this.oauth2AuthorizationService.findByToken(token.getState(), new OAuth2TokenType(OAuth2ParameterNames.STATE));
            if (authorization == null) {
                throw new IllegalStateException();
            }

            final OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
            if (authorizationRequest == null) {
                throw new IllegalStateException();
            }

            return authorizationRequest.getScopes();
        } else if (authentication instanceof OAuth2AuthorizationCodeRequestAuthenticationToken token) {
            return token.getScopes();
        } else {
            throw new IllegalStateException();
        }
    }

    @Override
    public void putValue(String key, Object value) {
        final HttpServletRequest request = AuthenticationHelper.getCurrentRequest().orElseThrow();
        request.setAttribute(CUSTOM_ATTRIBUTE_PREFIX + key, value);
    }

    @Override
    public <T> Optional<T> getValue(String key) {
        return AuthenticationHelper.getCurrentRequest()
                .map((request) -> request.getAttribute(CUSTOM_ATTRIBUTE_PREFIX + key))
                .map((attribute) -> (T) attribute);
    }

    @Override
    public OAuth2AuthorizationCodeRequestAuthenticationException error(OAuth2Error error) {
        final Authentication authentication = getAuthentication().orElseThrow(IllegalStateException::new);
        final OAuth2AuthorizationCodeRequestAuthenticationToken codeRequestAuthenticationToken;

        if (authentication instanceof OAuth2AuthorizationCodeRequestAuthenticationToken token) {
            codeRequestAuthenticationToken = token;
        } else if (authentication instanceof OAuth2AuthorizationConsentAuthenticationToken token) {
            codeRequestAuthenticationToken = codeRequestTokenForConsentToken(token);
        } else {
            throw new IllegalStateException();
        }

        return new OAuth2AuthorizationCodeRequestAuthenticationException(error, codeRequestAuthenticationToken);
    }

    private Optional<Authentication> getAuthentication() {
        return AuthenticationHelper.getCurrentRequest()
                .map((request) -> request.getAttribute(this.requestAttributeName))
                .filter(Authentication.class::isInstance)
                .map(Authentication.class::cast);
    }

    private OAuth2AuthorizationCodeRequestAuthenticationToken codeRequestTokenForConsentToken(OAuth2AuthorizationConsentAuthenticationToken token) {
        if (this.oauth2AuthorizationService == null) {
            throw new IllegalStateException("OAuth2AuthorizationService is not initialized");
        } else if (this.registeredClientRepository == null) {
            throw new IllegalStateException("RegisteredClientRepository is not initialized");
        }

        final OAuth2Authorization authorization = this.oauth2AuthorizationService.findByToken(token.getState(), new OAuth2TokenType(OAuth2ParameterNames.STATE));
        final RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(token.getClientId());
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
}
