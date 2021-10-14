package com.gw2auth.oauth2.server;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;

import static org.junit.jupiter.api.Assertions.*;

public final class Assertions {

    public static void assertInstantEquals(Instant expected, String actualAsISOStr) {
        assertInstantEquals(expected, actualAsISOStr, ChronoUnit.MILLIS);
    }

    public static void assertInstantEquals(Instant expected, String actualAsISOStr, TemporalUnit precision) {
        final Instant actual = Instant.parse(actualAsISOStr).truncatedTo(precision);
        assertEquals(expected.truncatedTo(precision), actual);
    }
}
