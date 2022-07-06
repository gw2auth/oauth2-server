package com.gw2auth.oauth2.server.util;

import com.gw2auth.oauth2.server.adapt.CookieBearerTokenResolver;
import com.gw2auth.oauth2.server.service.user.Gw2AuthTokenUserService;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUserV2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

@Component
public final class AuthenticationHelper {

    private static AuthenticationHelper instance;

    private final BearerTokenResolver bearerTokenResolver;
    private final Gw2AuthTokenUserService gw2AuthTokenUserService;

    @Autowired
    public AuthenticationHelper(Gw2AuthTokenUserService gw2AuthTokenUserService) {
        this.bearerTokenResolver = new CookieBearerTokenResolver(Constants.ACCESS_TOKEN_COOKIE_NAME);
        this.gw2AuthTokenUserService = gw2AuthTokenUserService;

        AuthenticationHelper.instance = this;
    }

    public static Optional<Gw2AuthUserV2> getUser() {
        return Optional.ofNullable(SecurityContextHolder.getContext().getAuthentication())
                .map(Authentication::getPrincipal)
                .filter(Gw2AuthUserV2.class::isInstance)
                .map(Gw2AuthUserV2.class::cast);
    }

    public static Optional<Gw2AuthUserV2> getUserPreauth() {
        if (AuthenticationHelper.instance == null) {
            throw new IllegalStateException("not initialized");
        }

        final HttpServletRequest request = Optional.ofNullable(RequestContextHolder.getRequestAttributes())
                .filter(ServletRequestAttributes.class::isInstance)
                .map(ServletRequestAttributes.class::cast)
                .map(ServletRequestAttributes::getRequest)
                .orElseThrow();

        final String bearer = AuthenticationHelper.instance.bearerTokenResolver.resolve(request);
        if (bearer == null) {
            return Optional.empty();
        }

        return AuthenticationHelper.instance.gw2AuthTokenUserService.resolveUserForToken(bearer);
    }

    public static Optional<Gw2AuthUserV2> getUser(boolean possiblyPreauth) {
        Optional<Gw2AuthUserV2> optional = getUser();

        if (possiblyPreauth) {
            optional = optional.or(AuthenticationHelper::getUserPreauth);
        }

        return optional;
    }
}
