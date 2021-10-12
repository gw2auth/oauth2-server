package com.gw2auth.oauth2.server;

import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.springframework.mock.web.MockHttpSession;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.util.stream.Stream;

@Retention(RetentionPolicy.RUNTIME)
@ParameterizedTest
@ArgumentsSource(WithGw2AuthLogin.MockHttpSessionArgumentProvider.class)
public @interface WithGw2AuthLogin {

    String issuer() default "test-issuer";
    String idAtIssuer() default "test-id-at-issuer";

    class MockHttpSessionArgumentProvider implements ArgumentsProvider {

        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            final MockHttpSession session = context.getStore(Gw2AuthLoginExtension.NAMESPACE).getOrComputeIfAbsent("session", (k) -> new MockHttpSession(), MockHttpSession.class);
            return Stream.of(Arguments.of(session));
        }
    }
}
