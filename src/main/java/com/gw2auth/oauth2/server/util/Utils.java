package com.gw2auth.oauth2.server.util;

import java.util.Spliterator;
import java.util.function.Consumer;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

public class Utils {

    public static Stream<String> split(String s, String delimiter) {
        return StreamSupport.stream(new StringSplitSpliterator(s, delimiter, -1), false);
    }

    public static Stream<String> split(String s, String delimiter, int limit) {
        return StreamSupport.stream(new StringSplitSpliterator(s, delimiter, limit), false);
    }

    public static Stream<QueryParam> parseQuery(String query) {
        return split(query, "&")
                .map(QueryParam::parse);
    }

    public static String lpad(Object v, char pad, int length) {
        final String s = v.toString();
        final int missing = length - s.length();
        if (missing < 1) {
            return s;
        }

        return String.valueOf(pad).repeat(missing) + s;
    }

    private static class StringSplitSpliterator implements Spliterator<String> {

        private static final int CHARACTERISTICS = ORDERED | NONNULL | IMMUTABLE;
        private static final int EXHAUSTED = -1;

        private final String s;
        private final String delimiter;
        private final int limit;
        private int offset;
        private int matches;

        private StringSplitSpliterator(String s, String delimiter, int limit) {
            this.s = s;
            this.delimiter = delimiter;
            this.limit = limit;
            this.offset = 0;
            this.matches = 0;
        }

        @Override
        public boolean tryAdvance(Consumer<? super String> action) {
            if (this.offset == EXHAUSTED) {
                return false;
            }

            final int index = this.s.indexOf(this.delimiter, this.offset);
            if (index == -1 || (this.limit > 0 && ++this.matches >= this.limit)) {
                action.accept(this.s.substring(this.offset));
                this.offset = EXHAUSTED;
            } else {
                action.accept(this.s.substring(this.offset, index));
                this.offset = index + this.delimiter.length();
            }

            return true;
        }

        @Override
        public Spliterator<String> trySplit() {
            return null;
        }

        @Override
        public long estimateSize() {
            return Long.MAX_VALUE;
        }

        @Override
        public int characteristics() {
            return CHARACTERISTICS;
        }
    }
}
