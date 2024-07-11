package com.gw2auth.oauth2.server.service.application.client;

import com.gw2auth.oauth2.server.util.UriPatternMatch;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@Component
public class RedirectUriValidatorImpl implements RedirectUriValidator {

    @Override
    public boolean validate(String redirectUri) {
        if (redirectUri == null || redirectUri.isEmpty()) {
            return false;
        }

        final String originalRedirectUri = redirectUri;
        String hash = null;

        if (redirectUri.indexOf('*') != -1) {
            hash = sha256(redirectUri);
            redirectUri = redirectUri.replace("*", hash);
        }

        final UriComponents uriComponents = UriComponentsBuilder.fromUriString(redirectUri).build();
        final String requestedRedirectHost = uriComponents.getHost();

        if (requestedRedirectHost == null || requestedRedirectHost.isEmpty() || requestedRedirectHost.equals("localhost")) {
            return false;
        }

        if (hash != null) {
            return UriPatternMatch.matches(originalRedirectUri, redirectUri);
        }

        return true;
    }

    private static String sha256(String redirectUri) {
        final MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        final byte[] bytes = md.digest(redirectUri.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
