package com.gw2auth.oauth2.server.service.client.registration;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;

@Component
public class RedirectUriValidatorImpl implements RedirectUriValidator {

    private final Method method;

    public RedirectUriValidatorImpl() throws ReflectiveOperationException {
        this.method = OAuth2AuthorizationCodeRequestAuthenticationProvider.class.getDeclaredMethod("isValidRedirectUri", String.class, RegisteredClient.class);
        this.method.setAccessible(true);
    }

    @Override
    public boolean validate(String redirectUri) {
        final RegisteredClient registeredClient = RegisteredClient.withId("0")
                .clientId("0")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(redirectUri)
                .build();

        try {
            return (boolean) this.method.invoke(null, redirectUri, registeredClient);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
