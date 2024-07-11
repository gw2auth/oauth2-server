package com.gw2auth.oauth2.server.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class UriPatternMatchTest {

    @Test
    public void validMatches() {
        assertTrue(UriPatternMatch.matches("https://gw2auth.com", "https://gw2auth.com"));
        assertTrue(UriPatternMatch.matches("https://*.gw2auth.com", "https://test.gw2auth.com"));
        assertTrue(UriPatternMatch.matches("https://*.gw2auth.com/*", "https://test.gw2auth.com/test"));
        assertTrue(UriPatternMatch.matches("https://*.*.gw2auth.com", "https://test.test.gw2auth.com"));
        assertTrue(UriPatternMatch.matches("https://gw2auth.com/*/a", "https://gw2auth.com/test/a"));
        assertTrue(UriPatternMatch.matches("https://gw2auth.com/a/*", "https://gw2auth.com/a/test"));
        assertTrue(UriPatternMatch.matches("https://gw2auth.com/*?q=test", "https://gw2auth.com/a?q=test"));
    }

    @Test
    public void invalidMatches() {
        assertFalse(UriPatternMatch.matches("https://gw2auth.com", "https://test.gw2auth.com"), "pattern without wildcard should only match on equal strings");
        assertFalse(UriPatternMatch.matches("https://*.gw2auth.com", "https://test.test.gw2auth.com"), "wildcard should only match one element");
        assertFalse(UriPatternMatch.matches("https://*.com", "https://gw2auth.com"), "host wildcard must be followed by at least 2 more known elements");
        assertFalse(UriPatternMatch.matches("https://*.*.com", "https://test.gw2auth.com"), "host wildcard must be followed by at least 2 more known elements");
        assertFalse(UriPatternMatch.matches("https://*.*.*", "https://test.gw2auth.com"), "host wildcard must be followed by at least 2 more known elements");
        assertFalse(UriPatternMatch.matches("https://*gw2auth.com", "https://testgw2auth.com"), "host wildcard must be in place of exactly one element");
        assertFalse(UriPatternMatch.matches("https://gw2auth.com/*", "https://gw2auth.com/a/b"), "path wildcard should only match one element");
        assertFalse(UriPatternMatch.matches("https://gw2auth.com/*?q=test", "https://gw2auth.com/a?q=somethingelse"), "query should match");
        assertFalse(UriPatternMatch.matches("https://gw2auth.com/?q=*", "https://gw2auth.com/?q=test"), "query wildcards not supported");
        assertFalse(UriPatternMatch.matches("*://gw2auth.com", "https://gw2auth.com"), "scheme wildcards not supported");
        assertFalse(UriPatternMatch.matches("https://user:password@*.gw2auth.com", "https://user:password@test.gw2auth.com"), "wildcards not supported for URIs with userinfo");
        assertFalse(UriPatternMatch.matches("https://*.gw2auth.com:443", "https://test.gw2auth.com:443"), "wildcards not supported for URIs with port");
        assertFalse(UriPatternMatch.matches("https://*.gw2auth.com/#fragment", "https://test.gw2auth.com/#fragment"), "wildcards not supported for URIs with fragment");
    }
}