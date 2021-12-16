package com.gw2auth.oauth2.server.util;

import java.util.*;
import java.util.concurrent.*;
import java.util.function.*;

class BatchImpl<ACC> implements Batch<ACC> {

    private final List<TaskAndConsumer<ACC, ?>> tasksAndConsumers;

    private BatchImpl(List<TaskAndConsumer<ACC, ?>> tasksAndConsumers) {
        this.tasksAndConsumers = List.copyOf(tasksAndConsumers);
    }

    private <T> RunningTaskContextImpl<ACC, T> submit(ExecutorService executorService, TaskAndConsumer<ACC, T> taskAndConsumer, long startedAt, long timeoutNanos) {
        final Future<? extends T> future = executorService.submit(taskAndConsumer.task());
        return new RunningTaskContextImpl<>(future, taskAndConsumer.consumer(), startedAt, timeoutNanos);
    }

    private ACC safeAccumulator(ACC accumulator, Supplier<? extends ACC> accumulatorSupplier) {
        if (accumulator == null) {
            accumulator = accumulatorSupplier.get();
        }

        return accumulator;
    }

    @Override
    public ACC execute(ExecutorService executorService, Supplier<? extends ACC> accumulatorSupplier, long timeout, TimeUnit timeUnit) {
        ACC accumulator = null;

        final long startedAt = System.nanoTime();
        final long timeoutNanos = timeUnit.toNanos(timeout);
        final Queue<RunningTaskContextImpl<ACC, ?>> runningTaskContexts = new ArrayDeque<>(this.tasksAndConsumers.size());

        RunningTaskContextImpl<ACC, ?> runningTaskContext;

        try {
            for (TaskAndConsumer<ACC, ?> taskAndConsumer : this.tasksAndConsumers) {
                runningTaskContexts.offer(submit(executorService, taskAndConsumer, startedAt, timeoutNanos));
            }

            long nanosLeft = timeoutNanos - (System.nanoTime() - startedAt);

            while (nanosLeft > 0L && (runningTaskContext = runningTaskContexts.poll()) != null) {
                accumulator = runningTaskContext.consume(safeAccumulator(accumulator, accumulatorSupplier), false);
                nanosLeft = timeoutNanos - (System.nanoTime() - startedAt);
            }
        } finally {
            // try to get all results for already finished tasks and cancel all tasks that are still in the queue
            while ((runningTaskContext = runningTaskContexts.poll()) != null) {
                accumulator = runningTaskContext.consume(safeAccumulator(accumulator, accumulatorSupplier), true);
                runningTaskContext.future.cancel(true);
            }
        }

        return safeAccumulator(accumulator, accumulatorSupplier);
    }

    private record TaskAndConsumer<ACC, T>(Callable<? extends T> task, BiFunction<? super ACC, RunningTaskContext<T>, ? extends ACC> consumer) {}

    private static class RunningTaskContextImpl<ACC, T> implements RunningTaskContext<T> {

        private final Future<? extends T> future;
        private final BiFunction<? super ACC, RunningTaskContext<T>, ? extends ACC> consumer;
        private final long startedAt;
        private final long timeoutNanos;
        private boolean allowDirectOnly;

        private RunningTaskContextImpl(Future<? extends T> future, BiFunction<? super ACC, RunningTaskContext<T>, ? extends ACC> consumer, long startedAt, long timeoutNanos) {
            this.future = future;
            this.consumer = consumer;
            this.startedAt = startedAt;
            this.timeoutNanos = timeoutNanos;
        }

        @Override
        public T get() throws ExecutionException, TimeoutException, InterruptedException {
            final T result;

            if (this.allowDirectOnly) {
                if (this.future.isDone()) {
                    result = this.future.get(1L, TimeUnit.NANOSECONDS);
                } else {
                    throw new TimeoutException();
                }
            } else {
                result = this.future.get(this.timeoutNanos - (System.nanoTime() - this.startedAt), TimeUnit.NANOSECONDS);
            }

            return result;
        }

        private ACC consume(ACC accumulator, boolean allowDirectOnly) {
            this.allowDirectOnly = allowDirectOnly;
            return this.consumer.apply(accumulator, this);
        }
    }

    static class BuilderImpl<ACC> implements Builder<ACC> {

        private final List<TaskAndConsumer<ACC, ?>> tasksAndConsumers;

        BuilderImpl() {
            this.tasksAndConsumers = new ArrayList<>();
        }

        @Override
        public <T> Builder<ACC> add(Callable<? extends T> callable, BiFunction<? super ACC, RunningTaskContext<T>, ? extends ACC> consumer) {
            this.tasksAndConsumers.add(new TaskAndConsumer<>(callable, consumer));
            return this;
        }

        @Override
        public Batch<ACC> build() {
            return new BatchImpl<>(this.tasksAndConsumers);
        }
    }
}
