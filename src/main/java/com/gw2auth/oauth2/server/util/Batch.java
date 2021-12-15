package com.gw2auth.oauth2.server.util;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.*;
import java.util.function.Supplier;

public class Batch<ACC> {

    private final List<Action<ACC, ?>> actions;

    private Batch(List<Action<ACC, ?>> actions) {
        this.actions = List.copyOf(actions);
    }

    private <T> TaskAndAction<ACC, T> submit(Action<ACC, T> action) {
        final ForkJoinTask<? extends T> task = ForkJoinPool.commonPool().submit(action.callable());
        return new TaskAndAction<>(task, action);
    }

    private <T> ACC tryGetAndAccumulate(ACC accumulator, TaskAndAction<ACC, T> taskAndAction, long nanosLeft) throws ExecutionException, InterruptedException, TimeoutException {
        final T result = taskAndAction.task().get(nanosLeft, TimeUnit.NANOSECONDS);
        return taskAndAction.action().accumulationFunction().accumulate(accumulator, ResultType.SUCCESS, result, null);
    }

    private <T> ACC tryGetAndAccumulateAllCases(ACC accumulator, TaskAndAction<ACC, T> taskAndAction, long nanosLeft) {
        try {
            accumulator = tryGetAndAccumulate(accumulator, taskAndAction, nanosLeft);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();

            taskAndAction.task().cancel(true);
            accumulator = taskAndAction.action().accumulationFunction().accumulate(accumulator, ResultType.CANCELLED, null, null);
        } catch (ExecutionException e) {
            accumulator = taskAndAction.action().accumulationFunction().accumulate(accumulator, ResultType.FAILED, null, e);
        } catch (TimeoutException e) {
            taskAndAction.task().cancel(true);
            accumulator = taskAndAction.action().accumulationFunction().accumulate(accumulator, ResultType.TIMEOUT, null, null);
        }

        return accumulator;
    }

    public ACC execute(Supplier<? extends ACC> accumulatorSupplier, long timeout, TimeUnit timeUnit) {
        ACC accumulator = accumulatorSupplier.get();

        final long timeoutAt = System.nanoTime() + timeUnit.toNanos(timeout);
        final Queue<TaskAndAction<ACC, ?>> tasksAndActions = new ArrayDeque<>(this.actions.size());

        TaskAndAction<ACC, ?> taskAndAction;

        try {
            for (Action<ACC, ?> action : this.actions) {
                tasksAndActions.offer(submit(action));
            }

            long nanosLeft = timeoutAt - System.nanoTime();

            while (nanosLeft > 0L && (taskAndAction = tasksAndActions.poll()) != null) {
                accumulator = tryGetAndAccumulateAllCases(accumulator, taskAndAction, nanosLeft);
                nanosLeft = timeoutAt - System.nanoTime();
            }
        } finally {
            // try to get all results for already finished tasks and cancel all tasks that are still in the queue
            while ((taskAndAction = tasksAndActions.poll()) != null) {
                if (taskAndAction.task().isDone()) {
                    accumulator = tryGetAndAccumulateAllCases(accumulator, taskAndAction, 0L);
                } else {
                    taskAndAction.task().cancel(true);
                    accumulator = taskAndAction.action().accumulationFunction().accumulate(accumulator, ResultType.CANCELLED, null, null);
                }
            }
        }

        return accumulator;
    }

    public static <ACC> Builder<ACC> builder() {
        return new Builder<>();
    }

    public static class Builder<ACC> {

        private final List<Action<ACC, ?>> actions;

        private Builder() {
            this.actions = new ArrayList<>();
        }

        public <T> Builder<ACC> add(Callable<? extends T> callable, AccumulationFunction<ACC, ? super T> accumulationFunction) {
            this.actions.add(new Action<>(callable, accumulationFunction));
            return this;
        }

        public Batch<ACC> build() {
            return new Batch<>(this.actions);
        }
    }

    private record Action<ACC, T>(Callable<? extends T> callable, AccumulationFunction<ACC, ? super T> accumulationFunction) {

    }

    private record TaskAndAction<ACC, T>(ForkJoinTask<? extends T> task, Action<ACC, T> action) {

    }

    public enum ResultType {

        SUCCESS,
        FAILED,
        TIMEOUT,
        CANCELLED
    }

    @FunctionalInterface
    public interface AccumulationFunction<ACC, T> {

        ACC accumulate(ACC accumulator, ResultType resultType, T result, ExecutionException exception);
    }
}
