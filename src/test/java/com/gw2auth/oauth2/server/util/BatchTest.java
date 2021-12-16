package com.gw2auth.oauth2.server.util;

import org.junit.jupiter.api.Test;
import org.testcontainers.shaded.com.google.common.util.concurrent.MoreExecutors;

import java.util.concurrent.TimeUnit;
import java.util.function.BiFunction;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class BatchTest {

    private static final BiFunction<String[], Batch.RunningTaskContext<String>, String[]> CONSUMER = (accumulator, context) -> {
        String result;
        try {
            result = context.get();
        } catch (Exception e) {
            result = e.getClass().getName();
        }

        final String[] concat = new String[accumulator.length + 1];
        System.arraycopy(accumulator, 0, concat, 0, accumulator.length);
        concat[concat.length - 1] = result;

        return concat;
    };

    @Test
    public void simple() {
        final Batch<String[]> batch = Batch.<String[]>builder()
                .add(() -> "hello", CONSUMER)
                .add(() -> "world", CONSUMER)
                .build();

        final String[] result = batch.execute(MoreExecutors.newDirectExecutorService(), () -> new String[0], Long.MAX_VALUE, TimeUnit.NANOSECONDS);
        assertArrayEquals(new String[]{"hello", "world"}, result);
    }

    @Test
    public void taskThatTimesOut() {
        final Batch<String[]> batch = Batch.<String[]>builder()
                .add(() -> {
                    Thread.sleep(10_000L);
                    return "world";
                }, CONSUMER)
                .add(() -> "hello", CONSUMER)
                .build();

        final String[] result = batch.execute(() -> new String[0], 1L, TimeUnit.SECONDS);
        assertArrayEquals(new String[]{"java.util.concurrent.TimeoutException", "hello"}, result);
    }

    @Test
    public void taskThatThrows() {
        final Batch<String[]> batch = Batch.<String[]>builder()
                .add(() -> "hello", CONSUMER)
                .add(() -> {
                    throw new RuntimeException();
                }, CONSUMER)
                .build();

        final String[] result = batch.execute(MoreExecutors.newDirectExecutorService(), () -> new String[0], 1L, TimeUnit.SECONDS);
        assertArrayEquals(new String[]{"hello", "java.util.concurrent.ExecutionException"}, result);
    }
}