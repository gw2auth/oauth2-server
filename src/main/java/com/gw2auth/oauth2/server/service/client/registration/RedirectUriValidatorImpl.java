package com.gw2auth.oauth2.server.service.client.registration;

import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

@Component
public class RedirectUriValidatorImpl implements RedirectUriValidator {

    @Override
    public boolean validate(String redirectUri) {
        if (redirectUri == null || redirectUri.isEmpty()) {
            return false;
        }

        final UriComponents uriComponents = UriComponentsBuilder.fromUriString(redirectUri).build();
        final String requestedRedirectHost = uriComponents.getHost();

        return requestedRedirectHost != null && !requestedRedirectHost.equals("localhost");
    }
}
