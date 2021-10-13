package com.gw2auth.oauth2.server.util;

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

    class Builder {

        private String name;
        private String value;

        public Builder() {

        }

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder value(String value) {
            this.value = value;
            return this;
        }

        public QueryParam build() {
            if (this.name == null) {
                throw new IllegalStateException("name must be set");
            }

            if (this.value == null) {
                return new QueryParamWithoutValue(this.name);
            } else {
                return new QueryParamWithValue(this.name, this.value);
            }
        }
    }
}
