package com.gw2auth.oauth2.server.util;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

public interface QueryParam {

    String name();
    String value();
    boolean hasValue();

    default Optional<String> optionalValue() {
        if (hasValue()) {
            return Optional.of(value());
        } else {
            return Optional.empty();
        }
    }

    static QueryParam parse(String rawPair) {
        final String[] pair = Utils.split(rawPair, "=").limit(2L).map((part) -> URLDecoder.decode(part, StandardCharsets.UTF_8)).toArray(String[]::new);

        if (pair.length >= 2) {
            return new QueryParamWithValue(pair[0], pair[1]);
        } else {
            return new QueryParamWithoutValue(pair[0]);
        }
    }

    record QueryParamWithValue(String name, String value) implements QueryParam {

        @Override
        public boolean hasValue() {
            return true;
        }
    }

    record QueryParamWithoutValue(String name) implements QueryParam {

        @Override
        public String value() {
            return null;
        }

        @Override
        public boolean hasValue() {
            return false;
        }
    }
}
