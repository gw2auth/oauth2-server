package com.gw2auth.oauth2.server.service.application;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

public interface AuthorizationCodeParamAccessor {

    Stream<Map.Entry<String, Object>> getAdditionalParameters();
    boolean isInCodeRequest();
    boolean isInConsentContext();
    Optional<OAuth2AuthorizationCodeRequestAuthenticationToken> getCodeRequest();
    Set<String> getRequestedScopes();
    void putValue(String key, Object value);
    <T> Optional<T> getValue(String key);
    OAuth2AuthorizationCodeRequestAuthenticationException error(OAuth2Error error);
}
