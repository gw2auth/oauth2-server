package com.gw2auth.oauth2.server.util;

@FunctionalInterface
public interface FunctionWithExc<IN, OUT, EXC extends Exception> {

    OUT apply(IN value) throws EXC;
}
