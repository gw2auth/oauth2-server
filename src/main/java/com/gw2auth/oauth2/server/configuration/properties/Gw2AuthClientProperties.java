package com.gw2auth.oauth2.server.configuration.properties;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.util.*;

@ConfigurationProperties(prefix = "com.gw2auth.client")
public record Gw2AuthClientProperties(
    @DefaultValue Map<String, List<Account>> account,
    @DefaultValue List<Registration> registration
) implements InitializingBean {

    @Override
    public void afterPropertiesSet() {
        validate();
    }

    private void validate() {
        for (Registration registration : this.registration) {
            if (!this.account.containsKey(registration.account())) {
                throw new IllegalStateException("Referenced account does not exist: " + registration.account());
            } else if (registration.clientId().isEmpty()) {
                throw new IllegalStateException("client-id must not be empty");
            }
        }
    }

    public record Registration(
        String account,
        String displayName,
        String clientId,
        String clientSecret,
        Set<String> authorizationGrantTypes,
        Set<String> redirectUris,
        int clientApiVersion
    ) {}

    public record Account(String issuer, String idAtIssuer) {}

}
