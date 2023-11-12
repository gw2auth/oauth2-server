package com.gw2auth.oauth2.server.configuration;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class TestClientRegistrationRepository implements ClientRegistrationRepository {

    private final Map<String, ClientRegistration> clientRegistrations;

    public TestClientRegistrationRepository() {
        this.clientRegistrations = new ConcurrentHashMap<>();
    }

    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        return this.clientRegistrations.get(registrationId);
    }

    public void prepareRegistrationId(String registrationId) {
        final ClientRegistration clientRegistration = ClientRegistration.withRegistrationId(registrationId)
                .clientName("Test")
                .clientId("dummy-id-" + registrationId)
                .clientSecret("dummy-secret")
                .scope("dummy-scope")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationUri("https://dummy.gw2auth.com/oauth2/authorize")
                .tokenUri("https://dummy.gw2auth.com/oauth2/token")
                .userInfoUri("https://dummy.gw2auth.com/oauth2/userinfo")
                .redirectUri("http://localhost/auth/oauth2/code/" + registrationId)
                .userNameAttributeName("sub")
                .build();

        this.clientRegistrations.put(registrationId, clientRegistration);
    }
}
