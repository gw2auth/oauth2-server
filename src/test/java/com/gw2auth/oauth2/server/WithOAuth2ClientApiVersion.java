package com.gw2auth.oauth2.server;

import com.gw2auth.oauth2.server.service.OAuth2ClientApiVersion;
import org.junit.jupiter.params.provider.ArgumentsSource;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
@ArgumentsSource(Gw2AuthArgumentsProvider.class)
public @interface WithOAuth2ClientApiVersion {

    OAuth2ClientApiVersion[] values() default {OAuth2ClientApiVersion.V0, OAuth2ClientApiVersion.V1};
}
