package com.gw2auth.oauth2.server.service.client.authorization;

import com.gw2auth.oauth2.server.adapt.CustomOAuth2AuthorizationCodeRequestAuthenticationProvider;

import java.util.Map;
import java.util.stream.Stream;

public interface AuthorizationCodeParamAccessor {

    AuthorizationCodeParamAccessor DEFAULT = new AuthorizationCodeParamAccessor() {
        @Override
        public Stream<Map.Entry<String, Object>> getAdditionalParameters() {
            return CustomOAuth2AuthorizationCodeRequestAuthenticationProvider.getAdditionalParameters();
        }

        @Override
        public boolean isInConsentContext() {
            return CustomOAuth2AuthorizationCodeRequestAuthenticationProvider.isInConsentContext();
        }
    };

    Stream<Map.Entry<String, Object>> getAdditionalParameters();
    boolean isInConsentContext();
}
