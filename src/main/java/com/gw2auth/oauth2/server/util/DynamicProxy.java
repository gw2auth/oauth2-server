package com.gw2auth.oauth2.server.util;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

public final class DynamicProxy implements InvocationHandler {

    private final Object src;
    private final Map<Method, Method> proxyMethods;

    private DynamicProxy(Object src, Map<Method, Method> proxyMethods) {
        this.src = src;
        this.proxyMethods = proxyMethods;
    }

    public static <SRC, TARGET> TARGET create(SRC src, Class<? super SRC> srcClass, Class<TARGET> targetClass) {
        if (!targetClass.isInterface()) {
            throw new IllegalArgumentException("only interfaces supported");
        }

        return (TARGET) Proxy.newProxyInstance(
                DynamicProxy.class.getClassLoader(),
                new Class<?>[]{targetClass},
                new DynamicProxy(src, Map.copyOf(buildProxyMethods(srcClass, targetClass)))
        );
    }

    private static Map<Method, Method> buildProxyMethods(Class<?> srcClass, Class<?> targetClass) {
        final Map<Method, Method> proxyMethods = new HashMap<>();

        for (Method targetMethod : targetClass.getMethods()) {
            final Method srcMethod = findSrcMethod(srcClass, targetMethod)
                    .orElseThrow(() -> new IllegalArgumentException("could not find matching method in src for [" + buildReadableMethodString(targetMethod) + "]"));

            proxyMethods.put(targetMethod, srcMethod);
        }

        return proxyMethods;
    }

    private static Optional<Method> findSrcMethod(Class<?> srcClass, Method targetMethod) {
        final String targetName = targetMethod.getName();
        final Class<?>[] targetParams = targetMethod.getParameterTypes();
        final Class<?> targetReturn = targetMethod.getReturnType();

        return findSrcMethodExact(srcClass, targetName, targetParams, targetReturn)
                .or(() -> findSrcMethodAny(srcClass, targetName, targetParams, targetReturn));
    }

    private static Optional<Method> findSrcMethodExact(Class<?> srcClass, String targetName, Class<?>[] targetParams, Class<?> targetReturn) {
        final Method srcMethod;
        try {
            srcMethod = srcClass.getMethod(targetName, targetParams);
        } catch (NoSuchMethodException e) {
            return Optional.empty();
        }

        if (targetReturn.isAssignableFrom(srcMethod.getReturnType())) {
            return Optional.of(srcMethod);
        }

        return Optional.empty();
    }

    private static Optional<Method> findSrcMethodAny(Class<?> srcClass, String targetName, Class<?>[] targetParams, Class<?> targetReturn) {
        for (Method srcMethod : srcClass.getMethods()) {
            if (srcMethod.getName().equals(targetName)) {
                final Class<?>[] srcParams = srcMethod.getParameterTypes();

                if (targetReturn.isAssignableFrom(srcMethod.getReturnType()) && srcParams.length == targetParams.length) {
                    boolean match = true;

                    for (int i = 0; match && i < targetParams.length; i++) {
                        final Class<?> srcParam = srcParams[i];
                        final Class<?> targetParam = targetParams[i];

                        if (!srcParam.isAssignableFrom(targetParam)) {
                            match = false;
                        }
                    }

                    if (match) {
                        return Optional.of(srcMethod);
                    }
                }
            }
        }

        return Optional.empty();
    }

    private static String buildReadableMethodString(Method method) {
        return new StringBuilder()
                .append(method.getReturnType().getSimpleName())
                .append(' ')
                .append(method.getName())
                .append('(')
                .append(
                        Arrays.stream(method.getParameterTypes())
                                .map(Class::getSimpleName)
                                .collect(Collectors.joining(", "))
                )
                .append(')')
                .toString();
    }

    @Override
    public Object invoke(Object proxy, Method target, Object[] args) throws Throwable {
        final Method src = this.proxyMethods.get(target);
        if (src == null) {
            throw new UnsupportedOperationException("method " + target + " is not supported");
        }

        return src.invoke(this.src, args);
    }
}
