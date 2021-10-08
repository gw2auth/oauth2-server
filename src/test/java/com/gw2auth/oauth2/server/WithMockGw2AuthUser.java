package com.gw2auth.oauth2.server;

import com.gw2auth.oauth2.server.service.user.Gw2AuthUser;
import org.springframework.security.test.context.support.WithSecurityContext;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
@WithSecurityContext(factory = WithMockGw2AuthUserSecurityContextFactory.class)
public @interface WithMockGw2AuthUser {

    long accountId() default 1L;
    String issuer() default "test-issuer";
    String idAtIssuer() default "test-id-at-issuer";
}
