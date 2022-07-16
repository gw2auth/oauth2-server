package com.gw2auth.oauth2.server;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

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

    public static void assertJsonEquals(Object expected, Object actual) throws Exception {
        final ObjectMapper mapper = new ObjectMapper();
        String expectedJson;
        String actualJson;

        if (expected instanceof String) {
            expectedJson = (String) expected;
        } else {
            expectedJson = mapper.writeValueAsString(expected);
        }

        if (actual instanceof String) {
            actualJson = (String) actual;
        } else {
            actualJson = mapper.writeValueAsString(actual);
        }

        assertEquals(mapper.readTree(expectedJson), mapper.readTree(actualJson));
    }
}
