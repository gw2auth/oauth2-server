package com.gw2auth.oauth2.server.util;

import java.util.concurrent.*;
import java.util.function.BiFunction;
import java.util.function.Supplier;

public interface Batch<ACC> {

    static <ACC> Builder<ACC> builder() {
        return new BatchImpl.BuilderImpl<>();
    }

    ACC execute(ExecutorService executorService, Supplier<? extends ACC> accumulatorSupplier, long timeout, TimeUnit timeUnit);

    default ACC execute(Supplier<? extends ACC> accumulatorSupplier, long timeout, TimeUnit timeUnit) {
        return execute(ForkJoinPool.commonPool(), accumulatorSupplier, timeout, timeUnit);
    }

    interface Builder<ACC> {

        <T> Builder<ACC> add(Callable<? extends T> callable, BiFunction<? super ACC, RunningTaskContext<T>, ? extends ACC> consumer);
        Batch<ACC> build();
    }

    interface RunningTaskContext<T> {

        T get() throws ExecutionException, TimeoutException, InterruptedException;
    }
}
