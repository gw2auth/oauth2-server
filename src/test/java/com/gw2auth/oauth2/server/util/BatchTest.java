package com.gw2auth.oauth2.server.util;

import org.junit.jupiter.api.Test;
import org.testcontainers.shaded.com.google.common.util.concurrent.MoreExecutors;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.BiFunction;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BatchTest {

    private static final BiFunction<Set<String>, Batch.RunningTaskContext<String>, Set<String>> CONSUMER = (accumulator, context) -> {
        String result;
        try {
            result = context.get();
        } catch (Exception e) {
            result = e.getClass().getName();
        }

        accumulator.add(result);

        return accumulator;
    };

    @Test
    public void simple() {
        final Batch<Set<String>> batch = Batch.<Set<String>>builder()
                .add(() -> "hello", CONSUMER)
                .add(() -> "world", CONSUMER)
                .build();

        final Set<String> result = batch.execute(MoreExecutors.newDirectExecutorService(), HashSet::new, Long.MAX_VALUE, TimeUnit.NANOSECONDS);
        assertEquals(2, result.size());
        assertTrue(result.contains("hello"));
        assertTrue(result.contains("world"));
    }

    @Test
    public void taskThatTimesOut() throws InterruptedException {
        final Batch<Set<String>> batch = Batch.<Set<String>>builder()
                .add(() -> {
                    Thread.sleep(10_000L);
                    return "world";
                }, CONSUMER)
                .add(() -> "hello", CONSUMER)
                .build();

        final ExecutorService executorService = Executors.newFixedThreadPool(2);
        final Set<String> result = batch.execute(executorService, HashSet::new, 1L, TimeUnit.SECONDS);

        executorService.shutdownNow();
        assertTrue(executorService.awaitTermination(500L, TimeUnit.MILLISECONDS));

        assertEquals(2, result.size());
        assertTrue(result.contains("hello"));
        assertTrue(result.contains("java.util.concurrent.TimeoutException"));
    }

    @Test
    public void taskThatThrows() {
        final Batch<Set<String>> batch = Batch.<Set<String>>builder()
                .add(() -> "hello", CONSUMER)
                .add(() -> {
                    throw new RuntimeException();
                }, CONSUMER)
                .build();

        final Set<String> result = batch.execute(MoreExecutors.newDirectExecutorService(), HashSet::new, 1L, TimeUnit.SECONDS);
        assertEquals(2, result.size());
        assertTrue(result.contains("hello"));
        assertTrue(result.contains("java.util.concurrent.ExecutionException"));
    }
}