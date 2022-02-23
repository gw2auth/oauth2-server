package com.gw2auth.oauth2.server.util;

import java.util.concurrent.*;
import java.util.function.BiFunction;
import java.util.function.Supplier;

public interface Batch<ACC> {

    static <R> Builder<R> builder() {
        return new BatchImpl.BuilderImpl<>();
    }

    ACC execute(ExecutorService executorService, Supplier<? extends ACC> accumulatorSupplier, long timeout, TimeUnit timeUnit);

    default ACC execute(Supplier<? extends ACC> accumulatorSupplier, long timeout, TimeUnit timeUnit) {
        return execute(ForkJoinPool.commonPool(), accumulatorSupplier, timeout, timeUnit);
    }

    @FunctionalInterface
    interface Task<T> {

        T call(long timeout, TimeUnit timeUnit) throws Exception;
    }

    interface Builder<ACC> {

        default <T> Builder<ACC> add(Callable<? extends T> callable, BiFunction<? super ACC, RunningTaskContext<T>, ? extends ACC> consumer) {
            return add((timeout, timeUnit) -> callable.call(), consumer);
        }

        <T> Builder<ACC> add(Task<? extends T> task, BiFunction<? super ACC, RunningTaskContext<T>, ? extends ACC> consumer);
        Batch<ACC> build();
    }

    @FunctionalInterface
    interface RunningTaskContext<T> {

        T get() throws ExecutionException, TimeoutException, InterruptedException;
    }
}
