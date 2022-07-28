package com.gw2auth.oauth2.server.adapt;

import com.gw2auth.oauth2.server.service.account.AccountFederationSession;
import com.gw2auth.oauth2.server.service.user.Gw2AuthLoginUser;
import com.gw2auth.oauth2.server.service.user.Gw2AuthTokenUserService;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUserV2;
import com.gw2auth.oauth2.server.util.Constants;
import com.gw2auth.oauth2.server.util.CookieHelper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.function.Supplier;

public class Gw2AuthSecurityContextRepository implements SecurityContextRepository {

    private final Gw2AuthInternalJwtConverter jwtConverter;
    private final Gw2AuthTokenUserService gw2AuthTokenUserService;
    private final BearerTokenResolver bearerTokenResolver;

    public Gw2AuthSecurityContextRepository(Gw2AuthInternalJwtConverter jwtConverter, Gw2AuthTokenUserService gw2AuthTokenUserService) {
        this.jwtConverter = jwtConverter;
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
    public Supplier<SecurityContext> loadContext(HttpServletRequest request) {
        return new SecurityContextSupplier(request);
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        final Authentication authentication = context.getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            final Object principal = authentication.getPrincipal();
            if (principal instanceof Gw2AuthLoginUser user) {
                final AccountFederationSession session = user.session();
                final Jwt jwt = this.jwtConverter.writeJWT(session.id(), session.creationTime(), session.expirationTime());
                CookieHelper.addCookie(request, response, Constants.ACCESS_TOKEN_COOKIE_NAME, jwt.getTokenValue(), jwt.getExpiresAt());
            }
        } else {
            CookieHelper.clearCookie(request, response, Constants.ACCESS_TOKEN_COOKIE_NAME);
        }
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        return loadContext(request).get() != null;
    }

    private final class SecurityContextSupplier implements Supplier<SecurityContext> {

        private final HttpServletRequest request;

        private SecurityContextSupplier(HttpServletRequest request) {
            this.request = request;
        }

        @Override
        public SecurityContext get() {
            SecurityContext securityContext = null;

            final String jwtString = Gw2AuthSecurityContextRepository.this.bearerTokenResolver.resolve(this.request);
            if (jwtString != null) {
                final Gw2AuthUserV2 user = Gw2AuthSecurityContextRepository.this.gw2AuthTokenUserService.resolveUserForToken(jwtString).orElse(null);
                if (user != null) {
                    securityContext = new SecurityContextImpl(new Gw2AuthAuthenticationManagerResolver.Gw2AuthUserAuthentication(user));
                }
            }

            return securityContext;
        }
    }
}
