package com.gw2auth.oauth2.server;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;

import static org.junit.jupiter.api.Assertions.*;

public final class Assertions {

    public static void assertInstantEquals(Instant expected, Instant actual) {
        assertInstantEquals(expected, actual, ChronoUnit.MILLIS);
    }

    public static void assertInstantEquals(Instant expected, Instant actual, TemporalUnit precision) {
        assertEquals(expected.truncatedTo(precision), actual.truncatedTo(precision));
    }
}
