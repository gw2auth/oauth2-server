package com.gw2auth.oauth2.server.service.client.registration;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Objects;
import java.util.stream.Stream;

public class SpringRegisteredClient extends RegisteredClient {
    private final ClientRegistration gw2AuthClient;

    protected SpringRegisteredClient(RegisteredClient springClient, ClientRegistration gw2AuthClient) {
        this.gw2AuthClient = Objects.requireNonNull(gw2AuthClient);

        Stream.concat(Arrays.stream(RegisteredClient.class.getDeclaredFields()), Arrays.stream(RegisteredClient.class.getFields()))
                .forEach((field) -> {
                    try {
                        if (!Modifier.isStatic(field.getModifiers())) {
                            field.setAccessible(true);
                            field.set(this, field.get(springClient));
                        }
                    } catch (ReflectiveOperationException e) {
                        throw new RuntimeException(e);
                    }
                });
    }

    public ClientRegistration getGw2AuthClientRegistration() {
        return this.gw2AuthClient;
    }
}
