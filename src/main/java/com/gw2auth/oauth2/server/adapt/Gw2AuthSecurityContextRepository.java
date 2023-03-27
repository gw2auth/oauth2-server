package com.gw2auth.oauth2.server.adapt;

import com.gw2auth.oauth2.server.service.user.Gw2AuthTokenUserService;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUserV2;
import com.gw2auth.oauth2.server.util.Constants;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;

import java.util.function.Supplier;

public class Gw2AuthSecurityContextRepository implements SecurityContextRepository {

    private final Gw2AuthTokenUserService gw2AuthTokenUserService;
    private final BearerTokenResolver bearerTokenResolver;

    public Gw2AuthSecurityContextRepository(Gw2AuthTokenUserService gw2AuthTokenUserService) {
        this.gw2AuthTokenUserService = gw2AuthTokenUserService;
        this.bearerTokenResolver = new CookieBearerTokenResolver(Constants.ACCESS_TOKEN_COOKIE_NAME);
    }

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        SecurityContext context = loadContext(requestResponseHolder.getRequest()).get();
        if (context == null) {
            context = SecurityContextHolder.createEmptyContext();
        }

        return context;
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {

    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        return loadContext(request).get() != null;
    }

    private Supplier<SecurityContext> loadContext(HttpServletRequest request) {
        return new SecurityContextSupplier(request);
    }

    private final class SecurityContextSupplier implements DeferredSecurityContext {

        private final HttpServletRequest request;

        private SecurityContextSupplier(HttpServletRequest request) {
            this.request = request;
        }

        @Override
        public SecurityContext get() {
            SecurityContext securityContext = null;

            final String jwtString = Gw2AuthSecurityContextRepository.this.bearerTokenResolver.resolve(this.request);
            if (jwtString != null) {
                final Gw2AuthUserV2 user = Gw2AuthSecurityContextRepository.this.gw2AuthTokenUserService.resolveUserForToken(this.request, jwtString).orElse(null);
                if (user != null) {
                    securityContext = new SecurityContextImpl(new Gw2AuthAuthenticationManagerResolver.Gw2AuthUserAuthentication(user));
                }
            }

            return securityContext;
        }

        @Override
        public boolean isGenerated() {
            return false;
        }
    }
}
