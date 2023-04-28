package com.gw2auth.oauth2.server.service.application.client;

public interface RedirectUriValidator {

    boolean validate(String redirectUri);
}
