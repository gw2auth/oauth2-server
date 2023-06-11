package com.gw2auth.oauth2.server.util;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class UtilsTest {

    @Test
    public void splitOneMatch() {
        final List<String> result = Utils.split("hello", ",").toList();

        assertEquals(1, result.size());
        assertEquals("hello", result.get(0));
    }

    @Test
    public void splitSimple() {
        final List<String> result = Utils.split("hello,world", ",").toList();

        assertEquals(2, result.size());
        assertEquals("hello", result.get(0));
        assertEquals("world", result.get(1));
    }

    @Test
    public void splitEmptyMatch() {
        final List<String> result = Utils.split("hello,,world", ",").toList();

        assertEquals(3, result.size());
        assertEquals("hello", result.get(0));
        assertEquals("", result.get(1));
        assertEquals("world", result.get(2));
    }

    @Test
    public void splitEmptyMatchStartEnd() {
        final List<String> result = Utils.split(",hello,world,", ",").toList();

        assertEquals(4, result.size());
        assertEquals("", result.get(0));
        assertEquals("hello", result.get(1));
        assertEquals("world", result.get(2));
        assertEquals("", result.get(3));
    }

    @Test
    public void splitWithLimit() {
        final List<String> result = Utils.split("h,e,l,l,o", ",", 2).toList();

        assertEquals(2, result.size());
        assertEquals("h", result.get(0));
        assertEquals("e,l,l,o", result.get(1));
    }

    @Test
    public void parseQueryNoValue() {
        final List<QueryParam> result = Utils.parseQuery("key").toList();

        assertEquals(1, result.size());
        assertEquals(new QueryParam.QueryParamWithoutValue("key"), result.get(0));
    }

    @Test
    public void parseQueryOneParam() {
        final List<QueryParam> result = Utils.parseQuery("key=value").toList();

        assertEquals(1, result.size());
        assertEquals(new QueryParam.QueryParamWithValue("key", "value"), result.get(0));
    }

    @Test
    public void parseQueryOneParamSpecialChars() {
        final List<QueryParam> result = Utils.parseQuery("hello%20world=world%20hello").toList();

        assertEquals(1, result.size());
        assertEquals(new QueryParam.QueryParamWithValue("hello world", "world hello"), result.get(0));
    }

    @Test
    public void parseQuerySameNameTwice() {
        final List<QueryParam> result = Utils.parseQuery("hello=world1&hello=world2").toList();

        assertEquals(2, result.size());
        assertEquals(new QueryParam.QueryParamWithValue("hello", "world1"), result.get(0));
        assertEquals(new QueryParam.QueryParamWithValue("hello", "world2"), result.get(1));
    }

    @Test
    public void parseComplexQuery() {
        final List<QueryParam> result = Utils.parseQuery("sdd.%2C%2Fs%28%265dsad%3D%7D%3D%22sd%5C%5Cds=_-%26%3D%24%3Faaalele%7C%7Ba%7D").toList();

        assertEquals(1, result.size());
        assertEquals(new QueryParam.QueryParamWithValue("sdd.,/s(&5dsad=}=\"sd\\\\ds", "_-&=$?aaalele|{a}"), result.get(0));
    }

    @Test
    public void lpadNotNeeded() {
        assertEquals("abcdef", Utils.lpad("abcdef", '0', 3));
    }

    @Test
    public void lpad() {
        assertEquals("&&&&abcdef", Utils.lpad("abcdef", '&', 10));
    }
}