package com.gw2auth.oauth2.server.util;

import org.slf4j.MDC;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

public final class ComposedMDCCloseable implements AutoCloseable {

    private final Iterable<MDC.MDCCloseable> mdcCloseables;

    public ComposedMDCCloseable(Iterable<MDC.MDCCloseable> mdcCloseables) {
        this.mdcCloseables = mdcCloseables;
    }

    @Override
    public void close() {
        RuntimeException first = null;

        for (MDC.MDCCloseable mdcCloseable : this.mdcCloseables) {
            try {
                mdcCloseable.close();
            } catch (Exception e) {
                first = wrap(first, e);
            }
        }

        if (first != null) {
            throw first;
        }
    }

    public static ComposedMDCCloseable create(Map<String, String> fields) {
        return create(fields, Objects::toString);
    }

    public static <T> ComposedMDCCloseable create(Map<String, T> fields, Function<? super T, String> toStringFunction) {
        final List<MDC.MDCCloseable> mdcCloseables = new ArrayList<>();
        for (Map.Entry<String, T> entry : fields.entrySet()) {
            mdcCloseables.add(MDC.putCloseable(entry.getKey(), toStringFunction.apply(entry.getValue())));
        }

        return new ComposedMDCCloseable(mdcCloseables);
    }

    private static RuntimeException wrap(RuntimeException first, Exception curr) {
        if (first == null) {
            return new RuntimeException(curr);
        }

        first.addSuppressed(curr);
        return first;
    }
}
