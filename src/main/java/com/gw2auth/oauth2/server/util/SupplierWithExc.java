package com.gw2auth.oauth2.server.util;

@FunctionalInterface
public interface SupplierWithExc<T, EXC extends Exception> {

    T get() throws EXC;
}
