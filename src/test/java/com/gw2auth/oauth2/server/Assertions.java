package com.gw2auth.oauth2.server;

import com.fasterxml.jackson.databind.JsonNode;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;

public final class Assertions {

    public static void assertInstantEquals(Instant expected, String actualAsISOStr) {
        assertInstantEquals(expected, Instant.parse(actualAsISOStr));
    }

    public static void assertInstantEquals(Instant expected, Instant actual) {
        assertInstantEquals(expected, actual, ChronoUnit.MILLIS);
    }

    public static void assertInstantEquals(Instant expected, Instant actual, TemporalUnit precision) {
        assertEquals(expected.truncatedTo(precision), actual.truncatedTo(precision));
    }

    public static void assertJsonArrayContainsExactly(JsonNode node, Set<String> expectedValues) {
        assertJsonArrayContainsExactly(node, expectedValues, JsonNode::textValue);
    }

    public static <T> void assertJsonArrayContainsExactly(JsonNode node, Set<? extends T> expectedValues, Function<? super JsonNode, ? extends T> getter) {
        assertTrue(node.isArray());
        expectedValues = new HashSet<>(expectedValues);

        for (int i = 0; i < node.size(); i++) {
            if (!expectedValues.remove(getter.apply(node.get(i)))) {
                fail("Received unexpected value; expected exactly: " + expectedValues);
            }
        }

        assertTrue(expectedValues.isEmpty());
    }
}
