package com.gw2auth.oauth2.server;

import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

public class Gw2AuthArgumentsProvider implements ArgumentsProvider {

    @Override
    public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
        final Method method = context.getRequiredTestMethod();
        final WithGw2AuthLogin withGw2AuthLogin = method.getDeclaredAnnotation(WithGw2AuthLogin.class);
        final WithOAuth2ClientApiVersion withOAuth2ClientApiVersion = method.getDeclaredAnnotation(WithOAuth2ClientApiVersion.class);

        final List<Object> arguments = new ArrayList<>();

        if (withGw2AuthLogin != null) {
            // has to be created here because this happens first
            final SessionHandle sessionHandle = context.getStore(Gw2AuthLoginExtension.NAMESPACE).getOrComputeIfAbsent("cookies", k -> new SessionHandle(), SessionHandle.class);
            arguments.add(sessionHandle);
        }

        if (withOAuth2ClientApiVersion != null) {
            return Arrays.stream(withOAuth2ClientApiVersion.values())
                    .map((v) -> {
                        final List<Object> copy = new ArrayList<>(arguments);
                        copy.add(v);
                        return copy;
                    })
                    .map(List::toArray)
                    .map(Arguments::of);
        } else {
            return Stream.of(Arguments.of(arguments.toArray()));
        }
    }
}