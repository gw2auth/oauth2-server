package com.gw2auth.oauth2.server.service.application;

import com.gw2auth.oauth2.server.adapt.CustomOAuth2ServerAuthenticationProviders;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

public interface AuthorizationCodeParamAccessor {

    AuthorizationCodeParamAccessor DEFAULT = new AuthorizationCodeParamAccessor() {
        @Override
        public Stream<Map.Entry<String, Object>> getAdditionalParameters() {
            return CustomOAuth2ServerAuthenticationProviders.getAdditionalParameters();
        }

        @Override
        public boolean isInCodeRequest() {
            return CustomOAuth2ServerAuthenticationProviders.isInCodeRequest();
        }

        @Override
        public boolean isInConsentContext() {
            return CustomOAuth2ServerAuthenticationProviders.isInConsentContext();
        }

        @Override
        public Optional<OAuth2AuthorizationCodeRequestAuthenticationToken> getCodeRequest() {
            return CustomOAuth2ServerAuthenticationProviders.getCodeRequest();
        }

        @Override
        public Set<String> getRequestedScopes() {
            return CustomOAuth2ServerAuthenticationProviders.getRequestedScopes();
        }

        @Override
        public void putValue(String key, Object value) {
            CustomOAuth2ServerAuthenticationProviders.putValue(key, value);
        }

        @Override
        public <T> Optional<T> getValue(String key) {
            return CustomOAuth2ServerAuthenticationProviders.getValue(key);
        }

        @Override
        public OAuth2AuthorizationCodeRequestAuthenticationException error(OAuth2Error error) {
            return CustomOAuth2ServerAuthenticationProviders.error(error);
        }
    };

    Stream<Map.Entry<String, Object>> getAdditionalParameters();
    boolean isInCodeRequest();
    boolean isInConsentContext();
    Optional<OAuth2AuthorizationCodeRequestAuthenticationToken> getCodeRequest();
    Set<String> getRequestedScopes();
    void putValue(String key, Object value);
    <T> Optional<T> getValue(String key);
    OAuth2AuthorizationCodeRequestAuthenticationException error(OAuth2Error error);
}
