package com.gw2auth.oauth2.server.util;

import com.gw2auth.oauth2.server.service.user.Gw2AuthUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

public class AuthenticationHelper {

    public static Optional<Gw2AuthUser> getUser() {
        return Optional.ofNullable(SecurityContextHolder.getContext().getAuthentication())
                .map(Authentication::getPrincipal)
                .filter(Gw2AuthUser.class::isInstance)
                .map(Gw2AuthUser.class::cast);

    }
}
