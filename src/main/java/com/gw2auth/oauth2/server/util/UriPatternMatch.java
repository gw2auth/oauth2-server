package com.gw2auth.oauth2.server.util;

import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.*;

public final class UriPatternMatch {


    private enum Section {

        SCHEME,
        HOST,
        PATH,
        QUERY,
    }

    private record SkippedPart(String skipped, String remaining) {}

    private static class UriMatcher {

        private final String uri;
        private final int hostOffset;
        private final int pathOffset;
        private final int queryOffset;
        private int cursor;

        private UriMatcher(String scheme, String host, String path, String query) {
            String uri = scheme + "://";
            this.hostOffset = uri.length();

            uri += host;
            this.pathOffset = uri.length();

            uri += path;
            this.queryOffset = uri.length();

            if (query != null) {
                uri += "?" + query;
            }

            this.uri = uri;
            this.cursor = 0;
        }

        public String uri() {
            return this.uri;
        }

        public int find(String substr) {
            return this.uri.indexOf(substr, this.cursor);
        }

        public Map<Section, SkippedPart> advance(int index) {
            if (index > this.uri.length()) {
                throw new IndexOutOfBoundsException();
            }

            final Map<Section, SkippedPart> skippedSections = new EnumMap<>(Section.class);
            if (this.cursor < this.hostOffset && index > 0) {
                final int end = Math.min(this.hostOffset, index);
                final String skipped = this.uri.substring(this.cursor, end);
                final String remaining = this.uri.substring(end, this.hostOffset);

                skippedSections.put(Section.SCHEME, new SkippedPart(skipped, remaining));
            }

            if (this.cursor < this.pathOffset && index > this.hostOffset) {
                final int start = Math.max(this.cursor, this.hostOffset);
                final int end = Math.min(this.pathOffset, index);
                final String skipped = this.uri.substring(start, end);
                final String remaining = this.uri.substring(end, this.pathOffset);

                skippedSections.put(Section.HOST, new SkippedPart(skipped, remaining));
            }

            if (this.cursor < this.queryOffset && index > this.pathOffset) {
                final int start = Math.max(this.cursor, this.pathOffset);
                final int end = Math.min(this.queryOffset, index);
                final String skipped = this.uri.substring(start, end);
                final String remaining = this.uri.substring(end, this.queryOffset);

                skippedSections.put(Section.PATH, new SkippedPart(skipped, remaining));
            }

            if (index > this.queryOffset) {
                final int start = Math.max(this.cursor, this.queryOffset);
                final String skipped = this.uri.substring(start, index);
                final String remaining = this.uri.substring(index);

                skippedSections.put(Section.QUERY, new SkippedPart(skipped, remaining));
            }

            this.cursor = index;

            return skippedSections;
        }

        public Map<Section, SkippedPart> advanceEnd() {
            return advance(this.uri.length());
        }

        public boolean exhausted() {
            return this.cursor >= this.uri.length();
        }
    }

    private sealed interface Part {}

    private record Literal(String value) implements Part {}

    private record Wildcard() implements Part {}

    public static boolean matches(String pattern, String uri) {
        if (pattern.indexOf('*') == -1) {
            return pattern.equals(uri);
        }

        final UriComponents uriComponents = UriComponentsBuilder.fromUriString(uri).build();
        if (uriComponents.getUserInfo() != null || uriComponents.getPort() != -1 || uriComponents.getFragment() != null) {
            return false;
        } else if (uriComponents.getScheme() == null || uriComponents.getHost() == null || uriComponents.getPath() == null) {
            return false;
        }

        final UriMatcher matcher = new UriMatcher(
                uriComponents.getScheme(),
                uriComponents.getHost(),
                uriComponents.getPath(),
                uriComponents.getQuery()
        );

        if (!matcher.uri().equals(uri)) {
            // better be safe than sorry: don't attempt to match over something that doesn't match reality
            return false;
        }

        boolean withinWildcard = false;
        for (Part part : buildParts(pattern)) {
            switch (part) {
                case Literal p:
                    final int index = matcher.find(p.value());
                    if (index == -1) {
                        return false;
                    }

                    final Map<Section, SkippedPart> skippedSections = matcher.advance(index);
                    if (withinWildcard) {
                        if (!isValidWildcardSkip(skippedSections)) {
                            return false;
                        }

                        withinWildcard = false;
                    } else if (!skippedSections.isEmpty()) {
                        return false;
                    }

                    matcher.advance(index + p.value().length());
                    break;

                case Wildcard p:
                    withinWildcard = true;
                    break;
            }
        }

        if (withinWildcard) {
            final Map<Section, SkippedPart> skippedSections = matcher.advanceEnd();
            if (!isValidWildcardSkip(skippedSections)) {
                return false;
            }
        }

        return matcher.exhausted();
    }

    private static boolean isValidWildcardSkip(Map<Section, SkippedPart> skippedSections) {
        if (skippedSections.size() != 1) {
            // exactly one section might be (partially) skipped
            return false;
        }

        for (Map.Entry<Section, SkippedPart> entry : skippedSections.entrySet()) {
            final boolean validSkip = switch (entry.getKey()) {
                case HOST -> isValidHostSkip(entry.getValue());
                case PATH -> isValidPathSkip(entry.getValue());
                default -> false; // only host and path skips supported
            };

            if (!validSkip) {
                return false;
            }
        }

        return true;
    }

    private static boolean isValidHostSkip(SkippedPart part) {
        if (part.skipped().indexOf('.') != -1) {
            // not allowed to skip more than one element
            return false;
        }

        // remaining part must have at least 2 defined host parts ("*.gw2auth.com" is valid but "*.com" is not)
        return part.remaining().startsWith(".") && Utils.split(part.remaining(), ".").count() >= 3L;
    }

    private static boolean isValidPathSkip(SkippedPart part) {
        // not allowed to skip more than one element
        return part.skipped().indexOf('/') == -1;
    }

    private static List<Part> buildParts(String pattern) {
        final List<Part> parts = new ArrayList<>();

        int offset = 0;
        int index;
        while ((index = pattern.indexOf('*', offset)) != -1) {
            final String head = pattern.substring(offset, index);
            if (!head.isEmpty()) {
                parts.add(new Literal(head));
            }

            parts.add(new Wildcard());
            offset = index + 1;
        }

        final String tail = pattern.substring(offset);
        if (!tail.isEmpty()) {
            parts.add(new Literal(tail));
        }

        return parts;
    }
}
