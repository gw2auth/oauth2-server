package com.gw2auth.oauth2.server.configuration;

import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.config.MeterFilter;
import io.micrometer.core.instrument.config.MeterFilterReply;
import io.micrometer.core.instrument.logging.LoggingMeterRegistry;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Set;

@Configuration
public class MicrometerConfiguration {

    @Bean
    public MeterRegistry meterRegistry() {
        return new LoggingMeterRegistry();
    }

    @Bean
    public MeterFilter meterFilter() {
        final Set<String> denyGroups = Set.of("system", "process", "jvm");

        return new MeterFilter() {
            @Override
            public MeterFilterReply accept(Meter.Id id) {
                final String name = id.getName();
                final String group = name.substring(0, name.indexOf('.'));

                if (denyGroups.contains(group)) {
                    return MeterFilterReply.DENY;
                } else {
                    return MeterFilter.super.accept(id);
                }
            }
        };
    }
}
