package com.gw2auth.oauth2.server;

import org.hamcrest.core.IsAnything;
import org.hamcrest.core.IsEqual;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.test.web.client.RequestMatcher;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Optional;

import static org.springframework.test.web.client.match.MockRestRequestMatchers.queryParam;

public final class RequestMatchers {

    public static RequestMatcher matchAuthorizedRequest() {
        return queryParam("access_token", new IsAnything<>());
    }

    public static RequestMatcher matchAuthorizedRequest(String accessToken) {
        return queryParam("access_token", new IsEqual<>(accessToken));
    }

    public static Optional<String> extractAccessToken(ClientHttpRequest request) {
        final String token = UriComponentsBuilder.fromUri(request.getURI())
                .build()
                .getQueryParams()
                .getFirst("access_token");

        return Optional.ofNullable(token);
    }
}
