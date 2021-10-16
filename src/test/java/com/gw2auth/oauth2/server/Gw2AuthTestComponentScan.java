package com.gw2auth.oauth2.server;

import com.gw2auth.oauth2.server.configuration.Gw2RestConfiguration;
import com.gw2auth.oauth2.server.configuration.HazelcastHttpSessionConfiguration;
import com.gw2auth.oauth2.server.configuration.SelfProxyRestConfiguration;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
@ComponentScan(basePackageClasses = Application.class, excludeFilters = {
        @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE, classes = {SelfProxyRestConfiguration.class, Gw2RestConfiguration.class, HazelcastHttpSessionConfiguration.class})
})
public @interface Gw2AuthTestComponentScan {

}
