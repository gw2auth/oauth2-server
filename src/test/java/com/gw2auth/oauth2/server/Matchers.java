package com.gw2auth.oauth2.server;

import com.gw2auth.oauth2.server.util.Utils;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;
import org.hamcrest.collection.IsIterableContainingInAnyOrder;
import org.hamcrest.collection.IsMapContaining;
import org.hamcrest.core.IsAnything;
import org.hamcrest.core.IsEqual;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

public final class Matchers {

    public static Matcher<String> asUri(Matcher<? super UriComponents> matcher) {
        return new MappingMatcher<>("UriComponents", (uriStr) -> {
            final URI uri = URI.create(uriStr);

            final UriComponentsBuilder builder = UriComponentsBuilder.newInstance()
                    .host(uri.getHost())
                    .path(uri.getPath())
                    .fragment(uri.getFragment());

            Utils.parseQuery(uri.getRawQuery()).forEach((queryParam) -> {
                if (queryParam.hasValue()) {
                    builder.queryParam(queryParam.name(), queryParam.value());
                } else {
                    builder.queryParam(queryParam.name());
                }
            });

            return builder.build();
        }, matcher);
    }

    public static Matcher<String> asInstant(Matcher<? super Instant> matcher) {
        return new MappingMatcher<>("Instant", Instant::parse, matcher);
    }

    public static Matcher<? super Instant> instantWithinTolerance(Instant expected, Duration tolerance) {
        return instantWithinRange(expected.minus(tolerance), expected.plus(tolerance));
    }

    public static Matcher<? super Instant> instantWithinRange(Instant low, Instant high) {
        return new TypeSafeMatcher<Instant>() {
            @Override
            protected boolean matchesSafely(Instant item) {
                return item.isAfter(low) && item.isBefore(high);
            }

            @Override
            public void describeTo(Description description) {
                description.appendValue(low).appendText(" <= value <= ").appendValue(high);
            }
        };
    }

    public static Matcher<String> split(String delimiter, Matcher<? super List<String>> matcher) {
        return new MappingMatcher<>("split '" + delimiter + "'", (v) -> Utils.split(v, delimiter).collect(Collectors.toList()), matcher);
    }

    public static <T> Matcher<Iterable<? extends T>> containingAll(T... values) {
        final List<Matcher<? super T>> matchers = new ArrayList<>(values.length);

        for (T value: values) {
            matchers.add(new IsEqual<>(value));
        }

        return new IsIterableContainingInAnyOrder<>(matchers);
    }

    public static Matcher<MultiValueMap<String, String>> hasQueryParam(String name) {
        return hasQueryParam(name, new IsAnything<>());
    }

    public static Matcher<MultiValueMap<String, String>> hasQueryParam(String name, String value) {
        return hasQueryParam(name, new IsEqual<>(value));
    }

    public static Matcher<MultiValueMap<String, String>> hasQueryParam(String name, Matcher<? super String> matcher) {
        return hasQueryParam(name, List.of(matcher));
    }

    public static Matcher<MultiValueMap<String, String>> hasQueryParam(String name, Collection<Matcher<? super String>> matchers) {
        return new MappingMatcher<>("Map<String, List<String>>", (v) -> v, new IsMapContaining<>(new IsEqual<>(name), new IsIterableContainingInAnyOrder<>(matchers)));
    }

    public static class MappingMatcher<IN, OUT> extends TypeSafeMatcher<IN> {

        private final String description;
        private final Function<? super IN, ? extends OUT> mappingFunction;
        private final Matcher<? super OUT> downstream;

        public MappingMatcher(String description, Function<? super IN, ? extends OUT> mappingFunction, Matcher<? super OUT> downstream) {
            this.description = description;
            this.mappingFunction = mappingFunction;
            this.downstream = downstream;
        }

        @Override
        protected boolean matchesSafely(IN in) {
            return this.downstream.matches(this.mappingFunction.apply(in));
        }

        @Override
        public void describeTo(Description description) {
            description.appendText("mapping to [").appendText(this.description).appendText("] ").appendDescriptionOf(this.downstream);
        }
    }
}
