package com.gw2auth.oauth2.server.service.client;

import com.gw2auth.oauth2.server.adapt.CustomOAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

public interface AuthorizationCodeParamAccessor {

    AuthorizationCodeParamAccessor DEFAULT = new AuthorizationCodeParamAccessor() {
        @Override
        public Stream<Map.Entry<String, Object>> getAdditionalParameters() {
            return CustomOAuth2AuthorizationCodeRequestAuthenticationProvider.getAdditionalParameters();
        }

        @Override
        public boolean isInCodeRequest() {
            return CustomOAuth2AuthorizationCodeRequestAuthenticationProvider.isInCodeRequest();
        }

        @Override
        public boolean isInConsentContext() {
            return CustomOAuth2AuthorizationCodeRequestAuthenticationProvider.isInConsentContext();
        }

        @Override
        public Set<String> getRequestedScopes() {
            return CustomOAuth2AuthorizationCodeRequestAuthenticationProvider.getRequestedScopes();
        }

        @Override
        public void putValue(String key, Object value) {
            CustomOAuth2AuthorizationCodeRequestAuthenticationProvider.putValue(key, value);
        }

        @Override
        public <T> Optional<T> getValue(String key) {
            return CustomOAuth2AuthorizationCodeRequestAuthenticationProvider.getValue(key);
        }

        @Override
        public OAuth2AuthorizationCodeRequestAuthenticationException error(OAuth2Error error) {
            return CustomOAuth2AuthorizationCodeRequestAuthenticationProvider.error(error);
        }
    };

    Stream<Map.Entry<String, Object>> getAdditionalParameters();
    boolean isInCodeRequest();
    boolean isInConsentContext();
    Set<String> getRequestedScopes();
    void putValue(String key, Object value);
    <T> Optional<T> getValue(String key);
    OAuth2AuthorizationCodeRequestAuthenticationException error(OAuth2Error error);
}
