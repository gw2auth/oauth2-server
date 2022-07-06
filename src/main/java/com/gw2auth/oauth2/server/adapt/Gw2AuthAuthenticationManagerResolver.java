package com.gw2auth.oauth2.server.adapt;

import com.fasterxml.jackson.annotation.*;
import com.gw2auth.oauth2.server.service.user.Gw2AuthTokenUserService;
import com.gw2auth.oauth2.server.service.user.Gw2AuthUserV2;
import com.gw2auth.oauth2.server.util.Constants;
import com.gw2auth.oauth2.server.util.CookieHelper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.Objects;
import java.util.Optional;

public class Gw2AuthAuthenticationManagerResolver implements AuthenticationManagerResolver<HttpServletRequest>, AuthenticationManager {

    private final Gw2AuthTokenUserService gw2AuthTokenUserService;

    public Gw2AuthAuthenticationManagerResolver(Gw2AuthTokenUserService gw2AuthTokenUserService) {
        this.gw2AuthTokenUserService = gw2AuthTokenUserService;
    }

    @Override
    public AuthenticationManager resolve(HttpServletRequest context) {
        return this;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (authentication instanceof BearerTokenAuthenticationToken token) {
            return authenticate(token.getToken());
        } else {
            throw new IllegalArgumentException("expected BearerTokenAuthenticationToken");
        }
    }

    private Authentication authenticate(String token) throws AuthenticationException {
        final Optional<Gw2AuthUserV2> optionalGw2AuthUser = this.gw2AuthTokenUserService.resolveUserForToken(token);
        if (optionalGw2AuthUser.isEmpty()) {
            clearCookie();
            throw new InvalidBearerTokenException("invalid session token");
        }

        return new Gw2AuthUserAuthentication(optionalGw2AuthUser.get());
    }

    private void clearCookie() {
        final ServletRequestAttributes servletRequestAttributes = Optional.ofNullable(RequestContextHolder.getRequestAttributes())
                .filter(ServletRequestAttributes.class::isInstance)
                .map(ServletRequestAttributes.class::cast)
                .orElseThrow();

        final HttpServletRequest request = Objects.requireNonNull(servletRequestAttributes.getRequest());
        final HttpServletResponse response = Objects.requireNonNull(servletRequestAttributes.getResponse());

        CookieHelper.clearCookie(request, response, Constants.ACCESS_TOKEN_COOKIE_NAME);
    }

    @JsonAutoDetect(
            fieldVisibility = JsonAutoDetect.Visibility.NONE,
            setterVisibility = JsonAutoDetect.Visibility.NONE,
            getterVisibility = JsonAutoDetect.Visibility.NONE,
            isGetterVisibility = JsonAutoDetect.Visibility.NONE,
            creatorVisibility = JsonAutoDetect.Visibility.NONE
    )
    private static class Gw2AuthUserAuthentication implements Authentication {

        private final Gw2AuthUserV2 gw2AuthUser;
        private boolean isAuthenticated;

        public Gw2AuthUserAuthentication(@JsonProperty("user") Gw2AuthUserV2 gw2AuthUser) {
            this(gw2AuthUser, true);
        }

        @JsonCreator
        public Gw2AuthUserAuthentication(@JsonProperty("user") Gw2AuthUserV2 gw2AuthUser, @JsonProperty("isAuthenticated") boolean isAuthenticated) {
            this.gw2AuthUser = gw2AuthUser;
            this.isAuthenticated = isAuthenticated;
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return this.gw2AuthUser.getAuthorities();
        }

        @Override
        public Object getCredentials() {
            return this.gw2AuthUser;
        }

        @Override
        public Object getDetails() {
            return this.gw2AuthUser;
        }

        @Override
        @JsonGetter("user")
        public Object getPrincipal() {
            return this.gw2AuthUser;
        }

        @Override
        @JsonGetter("isAuthenticated")
        public boolean isAuthenticated() {
            return this.isAuthenticated;
        }

        @Override
        public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
            this.isAuthenticated = isAuthenticated;
        }

        @Override
        public String getName() {
            return this.gw2AuthUser.getName();
        }
    }
}
