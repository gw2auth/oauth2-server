package com.gw2auth.oauth2.server;

import com.gw2auth.oauth2.server.service.OAuth2ClientType;
import org.junit.jupiter.params.provider.ArgumentsSource;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
@ArgumentsSource(Gw2AuthArgumentsProvider.class)
public @interface WithOAuth2ClientType {

    OAuth2ClientType[] values() default {OAuth2ClientType.CONFIDENTIAL};
}
