package com.gw2auth.oauth2.server.util;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public sealed interface QueryParam {

    String name();

    static QueryParam parse(String rawPair) {
        final String[] pair = Utils.split(rawPair, "=", 2).map((part) -> URLDecoder.decode(part, StandardCharsets.UTF_8)).toArray(String[]::new);

        if (pair.length >= 2) {
            return new QueryParamWithValue(pair[0], pair[1]);
        } else {
            return new QueryParamWithoutValue(pair[0]);
        }
    }

    record QueryParamWithValue(String name, String value) implements QueryParam {}

    record QueryParamWithoutValue(String name) implements QueryParam {}
}
