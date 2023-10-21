package com.gw2auth.oauth2.server;

import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

public class Gw2AuthArgumentsProvider implements ArgumentsProvider {

    @Override
    public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
        final Method method = context.getRequiredTestMethod();
        final WithGw2AuthLogin withGw2AuthLogin = method.getDeclaredAnnotation(WithGw2AuthLogin.class);
        final WithOAuth2ClientApiVersion withOAuth2ClientApiVersion = method.getDeclaredAnnotation(WithOAuth2ClientApiVersion.class);
        final WithOAuth2ClientType withOAuth2ClientType = method.getDeclaredAnnotation(WithOAuth2ClientType.class);

        Object[] sessions = null;

        if (withGw2AuthLogin != null) {
            // has to be created here because this happens first
            final SessionHandle sessionHandle = context.getStore(Gw2AuthLoginExtension.NAMESPACE).getOrComputeIfAbsent("cookies", k -> new SessionHandle(), SessionHandle.class);
            sessions = new Object[]{sessionHandle};
        }

        final List<List<Object>> matrix = buildMatrix(
                sessions,
                Optional.ofNullable(withOAuth2ClientApiVersion).map(WithOAuth2ClientApiVersion::values).orElse(null),
                Optional.ofNullable(withOAuth2ClientType).map(WithOAuth2ClientType::values).orElse(null)
        );

        return matrix.stream()
                .map(List::toArray)
                .map(Arguments::of);
    }

    private static List<List<Object>> buildMatrix(Object[]... values) {
        final List<List<Object>> matrix = new ArrayList<>();

        final int[] idx = new int[values.length];
        boolean exhausted = false;

        while (!exhausted) {
            final List<Object> arguments = new ArrayList<>();

            for (int i = 0; i < values.length; i++) {
                if (values[i] != null) {
                    arguments.add(values[i][idx[i]]);
                }
            }

            boolean finished = false;

            for (int i = values.length - 1; !finished && i >= 0; i--) {
                if (values[i] != null) {
                    if (++idx[i] >= values[i].length) {
                        idx[i] = 0;
                    } else {
                        finished = true;
                    }
                }
            }

            if (!finished) {
                exhausted = true;
            }

            matrix.add(arguments);
        }

        return matrix;
    }
}