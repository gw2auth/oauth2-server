package com.gw2auth.oauth2.server.service.client.registration;

public interface RedirectUriValidator {

    boolean validate(String redirectUri);
}
