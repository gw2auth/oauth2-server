package com.gw2auth.oauth2.server;

import org.junit.jupiter.params.provider.ArgumentsSource;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
@ArgumentsSource(Gw2AuthArgumentsProvider.class)
public @interface WithGw2AuthLogin {

    String issuer() default "test-issuer";
    String idAtIssuer() default "test-id-at-issuer";
    String countryCode() default SessionHandle.DEFAULT_COUNTRY_CODE;
    String city() default SessionHandle.DEFAULT_CITY;
    double latitude() default SessionHandle.DEFAULT_LATITUDE;
    double longitude() default SessionHandle.DEFAULT_LONGITUDE;
}
