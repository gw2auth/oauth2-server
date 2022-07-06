package com.gw2auth.oauth2.server;

import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.stream.Stream;

@Retention(RetentionPolicy.RUNTIME)
@ParameterizedTest
@ArgumentsSource(WithGw2AuthLogin.SessionCookieArgumentProvider.class)
public @interface WithGw2AuthLogin {

    String issuer() default "test-issuer";
    String idAtIssuer() default "test-id-at-issuer";

    class SessionCookieArgumentProvider implements ArgumentsProvider {

        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            // has to be created here because this happens first
            final CookieHolder cookieHolder = context.getStore(Gw2AuthLoginExtension.NAMESPACE).getOrComputeIfAbsent("cookies", k -> new CookieHolder(), CookieHolder.class);

            return Stream.of(Arguments.of(cookieHolder));
        }
    }
}
