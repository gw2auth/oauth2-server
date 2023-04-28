package com.gw2auth.oauth2.server;

import com.gw2auth.oauth2.server.service.Clocked;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.util.Collection;
import java.util.function.Predicate;

@Component
public class Gw2AuthClockedExtension implements BeforeEachCallback, AfterEachCallback, Clocked {

    private final Collection<Clocked> clockedBeans;

    @Autowired
    public Gw2AuthClockedExtension(Collection<Clocked> clockedBeans) {
        this.clockedBeans = clockedBeans;
    }

    @Override
    public void afterEach(ExtensionContext context) throws Exception {
        setClock(Clock.systemUTC());
    }

    @Override
    public void beforeEach(ExtensionContext context) throws Exception {

    }

    @Override
    public void setClock(Clock clock) {
        setClock(clock, (v) -> true);
    }

    public void setClockInclude(Clock clock, Collection<Class<?>> include) {
        setClock(clock, (v) -> include.stream().anyMatch((clazz) -> v.getClass().isAssignableFrom(clazz)));
    }

    public void setClockExclude(Clock clock, Collection<Class<?>> exclude) {
        setClock(clock, (v) -> exclude.stream().noneMatch((clazz) -> v.getClass().isAssignableFrom(clazz)));
    }

    public void setClock(Clock clock, Predicate<Clocked> predicate) {
        for (Clocked clocked : this.clockedBeans) {
            if (predicate.test(clocked)) {
                clocked.setClock(clock);
            }
        }
    }
}
